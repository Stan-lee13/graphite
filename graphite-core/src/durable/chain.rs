//! The audit trail's hash chain and keyed MAC (Round 30, G-07).
//!
//! Until Round 30 the trail was corruption-evident and nothing more: each
//! archive's index carried an unkeyed SHA-256 of the archive, which proves
//! the index was built from those bytes by something that could compute a
//! hash — so whoever could write the data directory could delete, reorder or
//! rewrite records and recompute everything that described them.
//!
//! Every record written since carries a `chain` object:
//!
//! - `seq`: its position in the trail, counted across rotation;
//! - `prev`: the `hash` of the record before it;
//! - `hash`: SHA-256 over a domain tag, `prev`, `seq` and the record's
//!   canonical JSON (keys sorted, `chain` excluded) — see [`link_hash`];
//! - with a key configured (`GRAPHITE_AUDIT_KEY_FILE`), `key_id` and `mac`:
//!   HMAC-SHA256 of `hash` under that key.
//!
//! WHAT EACH MODE PROVES — do not overstate it:
//!
//! - **Unkeyed** (no key file): *corruption-evident*. A deleted, inserted,
//!   reordered or edited record breaks the chain, so accidents, partial
//!   restores and careless edits are caught. A writer who can recompute
//!   SHA-256 can still rewrite the trail coherently from any point on.
//! - **Keyed**: *tamper-evident* against anyone without the key. A coherent
//!   rewrite needs the key; the key lives outside the data directory
//!   ([`AuditKey::load`] refuses one inside it). Truncating the newest
//!   records, or restoring an older backup, still yields a valid chain —
//!   only an anchored [`Checkpoint`] catches that.
//! - **Anchored**: a checkpoint exported to storage the writer cannot
//!   alter (WORM, object lock, a separate system) pins `(seq, hash)`;
//!   `graphite audit verify --checkpoint` then detects rewrite, truncation
//!   and a stale restore up to that point. Graphite writes checkpoints
//!   (`graphite audit checkpoint`, and at each rotation when
//!   `GRAPHITE_AUDIT_ANCHOR_DIR` is set); whether the place they are written
//!   to is immutable is the operator's storage, not something Graphite can
//!   establish or claim.
//!
//! Records written before Round 30 carry no `chain` ("legacy"). They are
//! never tamper-evident on their own. Since Round 38 (R37-2) a key-adoption
//! record carries a digest of the legacy records on disk when it was
//! written; under a key, a legacy record that no such digest covers is not
//! read, and `verify` reports it as not covered (exit 4), or as a break
//! (exit 1) when the chain was keyed from its first record.
//!
//! Link versions (Round 38, R37-5). Version 1 links (Rounds 30–37) hash
//! `prev`, `seq` and the content. Version 2 links also carry `trail`, a
//! random id the writer draws when it starts a chain (at genesis, or at its
//! first record after a version-1 head) and carries in every record after
//! it; it is hashed, so the MAC binds it, and a record copied from another
//! trail under the same key does not fit. Version-1 trails stay readable
//! and verifiable; a version-1 link after a version-2 one is a break.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The `chain.v` this module writes (Round 38: version 2, with `trail`).
pub const CHAIN_VERSION: u8 = 2;

/// The link version Rounds 30–37 wrote: no `trail`. Still read and verified.
pub const CHAIN_VERSION_1: u8 = 1;

/// `Checkpoint::v`.
pub const CHECKPOINT_VERSION: u8 = 1;

/// Bytes of a trail id (`ChainLink::trail`, hex).
pub const TRAIL_ID_BYTES: usize = 16;

/// The environment variable naming the audit key file.
pub const AUDIT_KEY_ENV: &str = "GRAPHITE_AUDIT_KEY_FILE";

/// The environment variable naming the directory checkpoints are written to
/// at each rotation.
pub const AUDIT_ANCHOR_ENV: &str = "GRAPHITE_AUDIT_ANCHOR_DIR";

/// The JSON key a record's chain link is stored under.
pub const CHAIN_FIELD: &str = "chain";

/// The smallest key accepted, in bytes (HMAC-SHA256's output size).
pub const MIN_KEY_BYTES: usize = 32;

/// The longest line of the trail anything reads, in bytes, newline excluded
/// (Round 38, T-15). Lines were read whole, so one line without a newline —
/// gigabytes of it — was read into memory by every reader and by `verify`.
/// A longer line is never buffered past this bound: `verify` reports it as a
/// break, no reader reads it, and the writer refuses to write one. No record
/// the server writes comes near it (a request body is at most 1 MiB, and
/// JSON escaping at most sextuples a byte).
pub const MAX_LINE_BYTES: usize = 8 << 20;

/// How one line read by `read_line_bounded` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineEnd {
    /// End of input before any byte.
    Eof,
    /// A newline (not kept).
    Terminated,
    /// End of input after some bytes: a final line without its newline.
    Unterminated,
    /// Longer than the bound: the buffer is left empty, and the line was
    /// read past (`terminated`: up to and including its newline).
    Oversized { terminated: bool },
}

/// Read one line of at most `max` bytes into `buf` (cleared first, newline
/// not kept): the bytes consumed, and how it ended. A longer line is
/// consumed to its end without being kept, so memory stays bounded by `max`
/// whatever the input (Round 38, T-15).
pub(crate) fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<(u64, LineEnd)> {
    buf.clear();
    let mut consumed = 0u64;
    let mut over = false;
    loop {
        let (used, done) = {
            let available = match reader.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                let end = if consumed == 0 {
                    LineEnd::Eof
                } else if over {
                    LineEnd::Oversized { terminated: false }
                } else {
                    LineEnd::Unterminated
                };
                return Ok((consumed, end));
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let chunk = &available[..newline.unwrap_or(available.len())];
            if !over {
                if buf.len() + chunk.len() > max {
                    over = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            match newline {
                Some(i) => (i + 1, true),
                None => (available.len(), false),
            }
        };
        reader.consume(used);
        consumed += used as u64;
        if done {
            let end = if over {
                LineEnd::Oversized { terminated: true }
            } else {
                LineEnd::Terminated
            };
            return Ok((consumed, end));
        }
    }
}

const LINK_DOMAIN: &[u8] = b"graphite-audit-chain-v1\0";
const LINK_DOMAIN_V2: &[u8] = b"graphite-audit-chain-v2\0";
const LEGACY_DOMAIN: &[u8] = b"graphite-audit-legacy-v1\0";
const TRAIL_ID_DOMAIN: &[u8] = b"graphite-audit-trail-id-v1\0";
const MAC_DOMAIN: &[u8] = b"graphite-audit-mac-v1\0";
const CHECKPOINT_DOMAIN: &[u8] = b"graphite-audit-checkpoint-v1\0";
const KEY_ID_DOMAIN: &[u8] = b"graphite-audit-key-id-v1\0";
const INDEX_MAC_DOMAIN: &[u8] = b"graphite-audit-index-v1\0";

/// The `prev` of the first record of a chain.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// `Checkpoint::kind`.
pub const CHECKPOINT_KIND: &str = "graphite-audit-checkpoint";

/// A secret key for the audit trail's MACs.
///
/// `Debug` never prints the key material.
#[derive(Clone)]
pub struct AuditKey {
    id: String,
    key: Vec<u8>,
}

/// The key material is wiped when a key is dropped (Round 34, A-7): it
/// used to stay in freed memory, where a core dump or a later allocation
/// could carry it.
impl Drop for AuditKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroes every byte, spare capacity included, and empties the Vec.
        self.key.zeroize();
        #[cfg(test)]
        if self.key.is_empty() {
            KEYS_WIPED.with(|n| n.set(n.get() + 1));
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Keys wiped on this thread (tests: a structural witness that `Drop`
    /// wipes, since freed memory cannot be read back).
    pub(crate) static KEYS_WIPED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl std::fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditKey")
            .field("id", &self.id)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl AuditKey {
    /// A key from raw material: at least [`MIN_KEY_BYTES`] bytes.
    pub fn from_bytes(material: &[u8]) -> Result<Self, String> {
        if material.len() < MIN_KEY_BYTES {
            return Err(format!(
                "an audit key must be at least {MIN_KEY_BYTES} bytes ({} given)",
                material.len()
            ));
        }
        let mut h = Sha256::new();
        h.update(KEY_ID_DOMAIN);
        h.update(material);
        let id = hex::encode(&h.finalize()[..8]);
        Ok(Self {
            id,
            key: material.to_vec(),
        })
    }

    /// Load a key file: hex text (whitespace around it ignored) encoding at
    /// least [`MIN_KEY_BYTES`] bytes — `openssl rand -hex 32 > audit.key`.
    ///
    /// Refused when the file resolves to a path inside `data_dir` (a key
    /// stored beside the log protects nothing from whoever can write the
    /// log) or, on Unix, when its group or others have any access to it.
    pub fn load(path: &Path, data_dir: Option<&Path>) -> Result<Self, String> {
        let resolved = std::fs::canonicalize(path)
            .map_err(|e| format!("audit key file {}: {e}", path.display()))?;
        if let Some(dir) = data_dir {
            if let Ok(dir) = std::fs::canonicalize(dir) {
                if resolved.starts_with(&dir) {
                    return Err(format!(
                        "audit key file {} is inside the data directory {}: whoever can rewrite the trail could read the key beside it. Keep it outside the data directory",
                        path.display(),
                        dir.display()
                    ));
                }
            }
        }
        let meta = std::fs::metadata(&resolved)
            .map_err(|e| format!("audit key file {}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("audit key file {} is not a file", path.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "audit key file {} is readable or writable by group or others (mode {mode:03o}); chmod 600 it",
                    path.display()
                ));
            }
        }
        // Windows: the file's ACL is not inspected; docs/ops/keys.md says
        // how to restrict it. The text and the decoded bytes are wiped once
        // the key holds its own copy.
        let text = zeroize::Zeroizing::new(
            std::fs::read_to_string(&resolved)
                .map_err(|e| format!("audit key file {}: {e}", path.display()))?,
        );
        let material = zeroize::Zeroizing::new(hex::decode(text.trim()).map_err(|_| {
            format!(
                "audit key file {} must hold hex text (e.g. `openssl rand -hex 32`)",
                path.display()
            )
        })?);
        Self::from_bytes(&material).map_err(|e| format!("audit key file {}: {e}", path.display()))
    }

    /// The key's public identifier: 16 hex digits of a domain-tagged SHA-256
    /// of the key. Names which key a record's MAC is under, for rotation.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn mac_of(&self, domain: &[u8], message: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.key, &[domain, message])
    }

    /// A running MAC of an archive index under this key (Round 38, R37-12):
    /// the index's bytes are fed to it as they are written or read.
    pub(crate) fn index_mac(&self) -> HmacSha256 {
        let mut m = HmacSha256::new(&self.key);
        m.update(INDEX_MAC_DOMAIN);
        m
    }

    /// The key id as its 8 bytes.
    pub(crate) fn id_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        if let Ok(b) = hex::decode(&self.id) {
            if b.len() == 8 {
                out.copy_from_slice(&b);
            }
        }
        out
    }
}

/// HMAC-SHA256 (RFC 2104), fed incrementally.
pub(crate) struct HmacSha256 {
    inner: Sha256,
    opad: [u8; 64],
}

impl HmacSha256 {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= block[i];
            opad[i] ^= block[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        Self { inner, opad }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    pub(crate) fn finalize(self) -> [u8; 32] {
        let inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.opad);
        outer.update(inner);
        outer.finalize().into()
    }
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new(key);
    for p in parts {
        m.update(p);
    }
    m.finalize()
}

/// Equality that takes the same time wherever the inputs differ.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One record's link in the chain, as stored under `chain`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLink {
    pub v: u8,
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    /// The trail's id (version 2, Round 38): 16 random bytes, lowercase hex,
    /// the same in every record of one trail. Hashed, so the MAC binds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// Where the next record joins the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainHead {
    pub next_seq: u64,
    pub prev: [u8; 32],
    /// Whether the newest record carried a MAC: a keyed trail cannot be
    /// continued without a key.
    pub keyed: bool,
    /// The trail id the next record carries (version 2); `None` seals a
    /// version-1 link (a head read from a Round 30–37 record, before the
    /// writer draws an id for it).
    pub trail: Option<[u8; TRAIL_ID_BYTES]>,
}

impl ChainHead {
    pub fn genesis() -> Self {
        Self {
            next_seq: 0,
            prev: GENESIS,
            keyed: false,
            trail: None,
        }
    }

    pub(crate) fn after(link: &ChainLink, hash: [u8; 32]) -> Self {
        Self {
            next_seq: link.seq.saturating_add(1),
            prev: hash,
            keyed: link.mac.is_some(),
            trail: link.trail.as_deref().and_then(decode_trail),
        }
    }
}

/// A fresh trail id: SHA-256 over the clock, the process, `salt` and two
/// OS-seeded hasher states (std's `RandomState`), truncated. It has to be
/// unique, not secret: it is written into every record.
pub(crate) fn new_trail_id(salt: &[u8]) -> [u8; TRAIL_ID_BYTES] {
    use std::hash::{BuildHasher, Hasher};
    let mut h = Sha256::new();
    h.update(TRAIL_ID_DOMAIN);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(nanos.to_be_bytes());
    h.update(std::process::id().to_be_bytes());
    h.update((salt.len() as u64).to_be_bytes());
    h.update(salt);
    for i in 0u8..2 {
        let mut s = std::collections::hash_map::RandomState::new().build_hasher();
        s.write_u8(i);
        h.update(s.finish().to_be_bytes());
    }
    let digest = h.finalize();
    let mut id = [0u8; TRAIL_ID_BYTES];
    id.copy_from_slice(&digest[..TRAIL_ID_BYTES]);
    id
}

/// A trail id from its hex form: exactly lowercase hex of
/// `TRAIL_ID_BYTES` bytes, so one id has one spelling.
fn decode_trail(s: &str) -> Option<[u8; TRAIL_ID_BYTES]> {
    let bytes: [u8; TRAIL_ID_BYTES] = hex::decode(s).ok()?.try_into().ok()?;
    (hex::encode(bytes) == s).then_some(bytes)
}

/// Write `v` as canonical JSON: object keys in byte order at every depth,
/// no whitespace, serde_json's escaping and number formatting. The writer
/// and the verifier both hash this, so neither depends on the order a map
/// happens to keep its keys in.
pub(crate) fn canonical_json(v: &serde_json::Value, out: &mut Vec<u8>) {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Serializing a string cannot fail.
                let _ = serde_json::to_writer(&mut *out, k);
                out.push(b':');
                canonical_json(&map[k], out);
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(item, out);
            }
            out.push(b']');
        }
        scalar => {
            let _ = serde_json::to_writer(&mut *out, scalar);
        }
    }
}

/// The chain hash of the record whose canonical JSON is `canonical`, at
/// position `seq`, after the record whose hash is `prev`. Every input is
/// length-framed or fixed-size, so no two different inputs share a
/// preimage.
pub(crate) fn link_hash(prev: &[u8; 32], seq: u64, canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LINK_DOMAIN);
    h.update(prev);
    h.update(seq.to_be_bytes());
    h.update((canonical.len() as u64).to_be_bytes());
    h.update(canonical);
    h.finalize().into()
}

/// `link_hash` of a version-2 link: the trail id is hashed too.
pub(crate) fn link_hash_v2(
    prev: &[u8; 32],
    seq: u64,
    trail: &[u8; TRAIL_ID_BYTES],
    canonical: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LINK_DOMAIN_V2);
    h.update(prev);
    h.update(trail);
    h.update(seq.to_be_bytes());
    h.update((canonical.len() as u64).to_be_bytes());
    h.update(canonical);
    h.finalize().into()
}

/// Seal `record` (a JSON object, without `chain`) onto the chain at `head`:
/// the line to write, and the head after it once it is written.
pub(crate) fn seal(
    mut record: serde_json::Map<String, serde_json::Value>,
    head: &ChainHead,
    key: Option<&AuditKey>,
) -> (String, ChainHead) {
    record.remove(CHAIN_FIELD);
    let value = serde_json::Value::Object(record);
    let mut canonical = Vec::new();
    canonical_json(&value, &mut canonical);
    // A head with a trail id seals a version-2 link; one without (only a
    // test's, or a head read from a version-1 record before the writer drew
    // an id for it) a version-1 link.
    let hash = match &head.trail {
        Some(t) => link_hash_v2(&head.prev, head.next_seq, t, &canonical),
        None => link_hash(&head.prev, head.next_seq, &canonical),
    };
    let link = ChainLink {
        v: if head.trail.is_some() {
            CHAIN_VERSION
        } else {
            CHAIN_VERSION_1
        },
        seq: head.next_seq,
        prev: hex::encode(head.prev),
        hash: hex::encode(hash),
        trail: head.trail.map(hex::encode),
        key_id: key.map(|k| k.id().to_string()),
        mac: key.map(|k| hex::encode(k.mac_of(MAC_DOMAIN, &hash))),
    };
    let next = ChainHead::after(&link, hash);
    let serde_json::Value::Object(mut record) = value else {
        unreachable!("built from a map above")
    };
    // Serializing a plain-data struct cannot fail.
    record.insert(
        CHAIN_FIELD.to_string(),
        serde_json::to_value(&link).unwrap_or(serde_json::Value::Null),
    );
    // The line is the canonical JSON of the whole record, link included:
    // the one form `classify_line` accepts (Round 34). serde_json's own
    // serialization is byte-identical today (its map is ordered), but the
    // grammar must not depend on which serde_json features a build unifies.
    let mut line = Vec::new();
    canonical_json(&serde_json::Value::Object(record), &mut line);
    // canonical_json writes valid UTF-8 (serde_json's string escaping).
    (String::from_utf8(line).unwrap_or_default(), next)
}

/// The content field that makes a chained record a control record of the
/// chain itself rather than an audit record (Round 34).
pub const CONTROL_FIELD: &str = "audit_control";

/// `CONTROL_FIELD` of a key-adoption record.
pub const KEY_ADOPTION: &str = "key_adoption";

/// The content field of the first record a writer appends after a torn line
/// (Round 34): it names that line, so the walk can tell a crash the writer
/// saw from a line someone added.
pub const TORN_TAIL_FIELD: &str = "torn_tail";

/// The environment variable naming the previous audit key during a key
/// rotation (Round 34): the writer checks the newest record under it before
/// writing a key-adoption record under the new key.
pub const AUDIT_PREVIOUS_KEY_ENV: &str = "GRAPHITE_AUDIT_PREVIOUS_KEY_FILE";

/// A torn line — the unterminated end of the active file a crash left — that
/// a writer resumed past, as the next record it wrote names it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TornTail {
    /// Byte offset of the torn line in its file.
    pub offset: u64,
    /// Its length in bytes, without the newline the writer added after it.
    pub length: u64,
    /// SHA-256 of those bytes, hex.
    pub sha256: String,
}

impl TornTail {
    pub(crate) fn of(offset: u64, bytes: &[u8]) -> Self {
        Self {
            offset,
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }
}

/// The content of a key-adoption record (Round 34): the first record under a
/// key the chain was not under before. MAC'd under `key_id`; names the key
/// the chain was under (`None`: no key — the records before it were unkeyed)
/// and whether the writer checked the newest record under that key.
///
/// It is what makes a key change part of the chain: a key id that appears
/// without one is a break, and unkeyed records before one are covered by its
/// MAC through the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAdoption {
    pub audit_control: String,
    pub timestamp: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_key_id: Option<String>,
    pub previous_key_checked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub torn_tail: Option<TornTail>,
    /// The legacy records (no chain link) on disk when the adoption was
    /// written, per file holding any, oldest first (Round 38, R37-2): what
    /// the adoption vouches for. A legacy line it does not list is not
    /// covered; one inserted among those it lists breaks the digest. Pruning
    /// drops whole files from the front, so the files left must be a suffix
    /// of this list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<Vec<LegacyFile>>,
}

/// The legacy records of one file, as a key-adoption record lists them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyFile {
    pub records: u64,
    /// SHA-256 over a domain tag and each legacy line (length-framed), hex.
    pub sha256: String,
}

/// A running `LegacyFile` digest.
#[derive(Clone)]
pub(crate) struct LegacyDigest {
    records: u64,
    hasher: Sha256,
}

impl Default for LegacyDigest {
    fn default() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(LEGACY_DOMAIN);
        Self { records: 0, hasher }
    }
}

impl LegacyDigest {
    pub(crate) fn add(&mut self, line: &[u8]) {
        self.records += 1;
        self.hasher.update((line.len() as u64).to_be_bytes());
        self.hasher.update(line);
    }

    pub(crate) fn finish(&self) -> LegacyFile {
        LegacyFile {
            records: self.records,
            sha256: hex::encode(self.hasher.clone().finalize()),
        }
    }
}

/// Whether the legacy files on disk (`on_disk`, oldest first) are what
/// `listed` vouches for: the same files, or the newest of them when older
/// ones were pruned.
pub(crate) fn legacy_matches(listed: &[LegacyFile], on_disk: &[LegacyFile]) -> bool {
    on_disk.len() <= listed.len() && listed[listed.len() - on_disk.len()..] == *on_disk
}

/// The legacy lines of the trail (terminated lines without a chain link,
/// before the first line that carries one), per file holding any, oldest
/// first, with the short hash of each line. A file that cannot be read
/// holds nothing.
pub(crate) fn legacy_prefix(files: &[PathBuf]) -> Vec<(LegacyFile, Vec<[u8; 16]>)> {
    let mut out = Vec::new();
    for path in files {
        let Ok(file) = File::open(path) else {
            continue;
        };
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        let mut digest = LegacyDigest::default();
        let mut hashes = Vec::new();
        let mut chained = false;
        loop {
            match read_line_bounded(&mut reader, &mut line, MAX_LINE_BYTES) {
                Ok((_, LineEnd::Terminated)) => {}
                // A line over the bound may carry a link: the prefix ends.
                Ok((_, LineEnd::Oversized { terminated: true })) => {
                    chained = true;
                    break;
                }
                _ => break,
            }
            let record = line.as_slice();
            match classify_line(record) {
                LineClass::Legacy => {
                    digest.add(record);
                    hashes.push(short_hash(record));
                }
                LineClass::Chained(_) | LineClass::Invalid { chained: true, .. } => {
                    chained = true;
                    break;
                }
                _ => {}
            }
        }
        if digest.records > 0 {
            out.push((digest.finish(), hashes));
        }
        if chained {
            break;
        }
    }
    out
}

/// The first 16 bytes of a line's SHA-256: what a reader remembers of a
/// line it may admit later.
pub(crate) fn short_hash(bytes: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// `CONTROL_FIELD` of a tear acknowledgement.
pub const TEAR_ACKNOWLEDGEMENT: &str = "tear_acknowledgement";

/// The content of a tear acknowledgement (Round 34): an operator's record,
/// written by `graphite audit acknowledge-tear`, that a line which is not
/// JSON — a torn write a pre-Round-34 writer resumed past without naming it
/// — is a crash the operator has looked at. The walk then tolerates exactly
/// that line: the same bytes (`length`, `sha256`) at the same place
/// (`offset` in its file, after the record `after_seq`; `file` names the
/// file when the tear precedes every chained record). A line that is JSON
/// is never a tear and cannot be acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TearAcknowledgement {
    pub audit_control: String,
    pub timestamp: String,
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_seq: Option<u64>,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub torn_tail: Option<TornTail>,
}

impl TearAcknowledgement {
    /// Whether this acknowledges `tear`.
    pub fn names(&self, tear: &TornLine) -> bool {
        self.offset == tear.offset
            && self.length == tear.length
            && self.sha256 == tear.sha256
            && self.after_seq == tear.after_seq
            && (self.after_seq.is_some() || self.file == tear.file)
    }
}

/// A line the walk found that is not JSON and that no record names as a
/// torn write the writer resumed past.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TornLine {
    pub file: String,
    /// 1-based line number in that file.
    pub line: u64,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    /// The seq of the last chained record before it.
    pub after_seq: Option<u64>,
}

/// `CONTROL_FIELD` of a prune record.
pub const PRUNE: &str = "prune";

/// The content of a prune record (Round 38, R37-14): written by the writer,
/// before it deletes the oldest archives (`GRAPHITE_AUDIT_MAX_ARCHIVES`), or
/// by `graphite audit acknowledge-prune` for a trail pruned before prune
/// records existed. Each entry of `retained` is a place the trail may start
/// once archives are gone: the first chained record left after deleting one
/// more archive, by its `seq` and its `prev` (the hash of the last record
/// deleted). Deleting stops at the first archive that cannot be removed, so
/// the trail on disk always starts at one of them.
///
/// Until Round 38 a trail whose oldest record on disk was above seq 0 read
/// as "pruned" with nothing to say so: deleting the oldest archives, or the
/// oldest lines of one, passed `verify` (exit 0). A first record above seq 0
/// that no prune record in the chain names is now a break.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneRecord {
    pub audit_control: String,
    pub timestamp: String,
    pub retained: Vec<PruneBoundary>,
    /// Written by `graphite audit acknowledge-prune` (an operator's record of
    /// a prune nothing recorded), not by the writer that pruned.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub torn_tail: Option<TornTail>,
}

/// One place a pruned trail may start (`PruneRecord::retained`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneBoundary {
    pub first_seq: u64,
    /// The `prev` of the record at `first_seq`: the hash of the last record
    /// pruned, hex.
    pub last_pruned_hash: String,
}

/// The first chained record of `path`, as a `PruneBoundary`: `None` when
/// the file holds none, or when the first line carrying a link is not a
/// valid chained record.
pub(crate) fn first_chained(path: &Path) -> Option<PruneBoundary> {
    let mut reader = BufReader::new(File::open(path).ok()?);
    let mut line = Vec::new();
    loop {
        match read_line_bounded(&mut reader, &mut line, MAX_LINE_BYTES).ok()? {
            (_, LineEnd::Terminated) => {}
            (_, LineEnd::Oversized { terminated: true }) => continue,
            _ => return None,
        }
        match classify_line(&line) {
            LineClass::Chained(c) => {
                return Some(PruneBoundary {
                    first_seq: c.link.seq,
                    last_pruned_hash: c.link.prev.clone(),
                })
            }
            LineClass::Invalid { chained: true, .. } => return None,
            _ => {}
        }
    }
}

/// A control record of the chain itself.
#[derive(Debug, Clone)]
pub(crate) enum Control {
    KeyAdoption(KeyAdoption),
    TearAcknowledgement(TearAcknowledgement),
    Prune(PruneRecord),
}

/// A line that is a chained record: its bytes are the canonical form of its
/// content and link, and its content recomputes to its own hash. Nothing
/// here says it links to the record before it or that its MAC verifies —
/// that takes the walk, and a key.
#[derive(Debug, Clone)]
pub(crate) struct ChainedLine {
    pub link: ChainLink,
    pub hash: [u8; 32],
    /// The trail id of a version-2 link.
    pub trail: Option<[u8; TRAIL_ID_BYTES]>,
    pub torn_tail: Option<TornTail>,
    /// `Some` for a control record: what it is, or why it is not one.
    pub control: Option<Result<Control, String>>,
}

impl ChainedLine {
    fn adoption(&self) -> Option<Result<&KeyAdoption, &String>> {
        match &self.control {
            None | Some(Ok(Control::TearAcknowledgement(_))) | Some(Ok(Control::Prune(_))) => None,
            Some(Ok(Control::KeyAdoption(a))) => Some(Ok(a)),
            Some(Err(e)) => Some(Err(e)),
        }
    }
}

/// What one line of the trail is (Round 34): the ONE grammar the chain walk
/// and every reader apply.
///
/// Until Round 34 the walk parsed a line into `serde_json::Value` and the
/// readers parsed the same bytes into `AuditRecord`, and the two parsers
/// disagree: a duplicate key (the walk keeps the last, the derived
/// `Deserialize` refuses the line), a number such as `1e400` in a field the
/// record does not have (`Value` refuses it, the record skips it unread).
/// So a line could be read as a verdict by L8 while the walk counted it as
/// torn, or hidden from every reader while the walk verified its MAC.
/// A chained line is now valid only when its bytes ARE the canonical JSON of
/// what they parse to — keys sorted, no whitespace, serde_json's spelling of
/// every number and string — which leaves nothing for two parsers to read
/// differently.
#[derive(Debug, Clone)]
pub(crate) enum LineClass {
    /// Whitespace only.
    Blank,
    /// A JSON object with no `chain`: a record written before Round 30.
    /// Readable only before the first chained record of the trail.
    Legacy,
    Chained(Box<ChainedLine>),
    /// Not a record. `json`: the bytes parse as JSON (a torn write never
    /// does). `chained`: they carry a `chain` field.
    Invalid {
        seq: Option<u64>,
        reason: String,
        json: bool,
        chained: bool,
    },
}

/// Classify one line, without its newline.
pub(crate) fn classify_line(line: &[u8]) -> LineClass {
    if line.iter().all(u8::is_ascii_whitespace) {
        return LineClass::Blank;
    }
    let invalid =
        |seq: Option<u64>, reason: String, json: bool, chained: bool| LineClass::Invalid {
            seq,
            reason,
            json,
            chained,
        };
    let value: serde_json::Value = match serde_json::from_slice(line) {
        Ok(v) => v,
        Err(e) => {
            return invalid(
                None,
                format!(
                    "not a JSON record ({e}): a torn write, or bytes no writer of this trail wrote"
                ),
                false,
                false,
            )
        }
    };
    let Some(map) = value.as_object() else {
        return invalid(
            None,
            "a JSON value that is not an object".into(),
            true,
            false,
        );
    };
    let Some(raw_link) = map.get(CHAIN_FIELD) else {
        return LineClass::Legacy;
    };
    let named_seq = raw_link.get("seq").and_then(serde_json::Value::as_u64);
    let mut canonical = Vec::with_capacity(line.len());
    canonical_json(&value, &mut canonical);
    if canonical.as_slice() != line {
        return invalid(
            named_seq,
            "the line is not in the canonical form the writer emits (a duplicate key, whitespace, key order, or a number or string spelled differently): its bytes do not say what their parsed content says".into(),
            true,
            true,
        );
    }
    let serde_json::Value::Object(mut map) = value else {
        unreachable!("checked to be an object above")
    };
    let raw_link = map.remove(CHAIN_FIELD).unwrap_or(serde_json::Value::Null);
    let link: ChainLink = match serde_json::from_value(raw_link) {
        Ok(l) => l,
        Err(e) => return invalid(named_seq, format!("malformed chain link: {e}"), true, true),
    };
    let seq = Some(link.seq);
    let trail = match (link.v, link.trail.as_deref()) {
        (CHAIN_VERSION_1, None) => None,
        (CHAIN_VERSION, Some(t)) => match decode_trail(t) {
            Some(t) => Some(t),
            None => {
                return invalid(
                    seq,
                    "malformed chain link: `trail` is not 16 bytes of lowercase hex".into(),
                    true,
                    true,
                )
            }
        },
        (CHAIN_VERSION_1, Some(_)) => {
            return invalid(
                seq,
                "malformed chain link: a version-1 link carries no `trail`".into(),
                true,
                true,
            )
        }
        (CHAIN_VERSION, None) => {
            return invalid(
                seq,
                "malformed chain link: a version-2 link without its `trail`".into(),
                true,
                true,
            )
        }
        (v, _) => return invalid(seq, format!("unknown chain version {v}"), true, true),
    };
    let Some(prev) = decode32(&link.prev) else {
        return invalid(
            seq,
            "malformed chain link: `prev` is not 32 hex bytes".into(),
            true,
            true,
        );
    };
    let content = serde_json::Value::Object(map);
    let mut content_bytes = Vec::with_capacity(line.len());
    canonical_json(&content, &mut content_bytes);
    let hash = match &trail {
        Some(t) => link_hash_v2(&prev, link.seq, t, &content_bytes),
        None => link_hash(&prev, link.seq, &content_bytes),
    };
    if decode32(&link.hash) != Some(hash) {
        return invalid(
            seq,
            "the record does not match its own chain hash: its content was altered".into(),
            true,
            true,
        );
    }
    let serde_json::Value::Object(map) = content else {
        unreachable!("built from a map above")
    };
    let torn_tail = match map.get(TORN_TAIL_FIELD) {
        None => None,
        Some(v) => match serde_json::from_value::<TornTail>(v.clone()) {
            Ok(t) => Some(t),
            Err(e) => {
                return invalid(
                    seq,
                    format!("malformed `{TORN_TAIL_FIELD}`: {e}"),
                    true,
                    true,
                )
            }
        },
    };
    let control = map.get(CONTROL_FIELD).cloned().map(|kind| {
        let content = serde_json::Value::Object(map);
        match kind.as_str() {
            Some(KEY_ADOPTION) => serde_json::from_value::<KeyAdoption>(content)
                .map(Control::KeyAdoption)
                .map_err(|e| e.to_string()),
            Some(TEAR_ACKNOWLEDGEMENT) => serde_json::from_value::<TearAcknowledgement>(content)
                .map(Control::TearAcknowledgement)
                .map_err(|e| e.to_string()),
            Some(PRUNE) => serde_json::from_value::<PruneRecord>(content)
                .map(Control::Prune)
                .map_err(|e| e.to_string()),
            _ => Err(format!("unknown control record {kind}")),
        }
    });
    LineClass::Chained(Box::new(ChainedLine {
        link,
        hash,
        trail,
        torn_tail,
        control,
    }))
}

/// What the readers apply to every line (Round 34): whether a line may be
/// read as a record. Every reader — the scans behind the dashboard, the
/// active and archive index builders, `find_verification`,
/// `count_verifications`, the lifecycle readers and every index read-back —
/// goes through this, and through nothing else. A line without its newline
/// is never offered to it: a final line still in flight, or torn by a
/// crash, is not part of the trail, and never changes what the gate knows.
///
/// Round 38 (R37-2 … R37-5): the gate is the walk `verify` does, carried
/// across the trail's files in order (`Cursor`), not a judgement of each
/// line alone. A chained line is admitted only when
///
/// - it continues the last line admitted: the next `seq`, and `prev` that
///   line's hash (the first chained line on disk starts the walk, from
///   genesis at seq 0, or above 0 when older archives were pruned). A
///   genuine record copied to another position, or from another trail
///   under the same key, does not continue anything there (R37-5);
/// - a version-2 link carries the trail id the walk is under, and no
///   version-1 link follows a version-2 one;
/// - with keys held (`GateContext::keys`): its MAC verifies under one of
///   them, or it is under a key id that a checked key-adoption record names
///   as the key before it (`vouched`: a key rotated out of this reader's
///   reach) AND a checked key-adoption record covers it through the hash
///   chain, as an unkeyed record must be (`TrailFacts::covered`, Round 38,
///   R37-13). It used to be admitted on the adoption's word alone, so a
///   forgery under the vouched key that replaced a record — its MAC one the
///   reader cannot check, its link continuing the record before it — was
///   read in place of that record. It breaks the chain to the adoption, so
///   now nothing under the vouched key is covered, and the forgery is never
///   read;
/// - its key id is not one the chain moved away from: a key rotation is
///   one-way, and a record under a retired key after the rotation is never
///   read (R37-4). A key change without a key-adoption record (a rotation
///   written before Round 34) is accepted only before the first adoption
///   record, and, by a reader with keys, only when it holds both keys;
/// - an unkeyed record: never once the chain is keyed; and, by a reader
///   with keys, only when a checked key-adoption record covers it through
///   the hash chain (`TrailFacts::unkeyed`, R37-3). An unkeyed line at the
///   top of a trail keyed from genesis is covered by nothing.
///
/// A legacy line (no chain link) is read only before the first line that
/// carries one; by a reader with keys, only when a checked key-adoption
/// record lists it (`KeyAdoption::legacy`, R37-2).
///
/// A reader without a key checks no MAC: to it the trail is
/// corruption-evident only, as the walk without a key is.
#[derive(Debug, Clone)]
pub(crate) struct RecordGate {
    cur: Cursor,
    ctx: GateContext,
    /// Legacy lines of this file seen so far.
    legacy_in_file: u64,
    /// Pass 1 of `TrailFacts::covered`: unkeyed records and records under a
    /// vouched key, admitted tentatively, not yet covered by an adoption.
    pending: Vec<(u64, [u8; 16])>,
    /// Pass 1: unkeyed records a checked adoption covered.
    covered: Vec<(u64, [u8; 16])>,
}

/// Where the reader's walk is (Round 38): what it knows after the last line
/// it judged. Carried from one file of the trail to the next, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    /// A line carrying a chain link has been seen (even a broken one: a
    /// forged line never makes a legacy record after it readable).
    pub chain_began: bool,
    /// The last chained line admitted: its `seq` and hash.
    pub last: Option<(u64, [u8; 32])>,
    /// The key the chain is under at `last` (`None`: not keyed yet).
    pub chain_key: Option<String>,
    /// Keys the chain moved away from (R37-4): never again.
    pub retired: Vec<String>,
    /// A key-adoption record was admitted.
    pub adopted: bool,
    /// The trail id of the version-2 records admitted.
    pub trail: Option<[u8; TRAIL_ID_BYTES]>,
    /// A chained line of another trail was refused for its trail id alone:
    /// one whose MAC verifies under a key this reader holds (for a reader
    /// without a key, any valid chained line). Round 39 (R39-CB-1): two
    /// trails under one key are on disk, and which of them is this one is
    /// not knowable from the trail, since the pin is the newest record's id
    /// and the newest record is whoever appended last. A writer refuses to
    /// resume (`resume_head`), and a keyed read-only reader to open.
    pub other_trail: bool,
}

/// What a reader with keys learns once from the whole trail (Round 34
/// follow-up, Round 38), lazily, the first time a line needs it.
#[derive(Default)]
pub(crate) struct TrailFacts {
    adoptions: std::sync::OnceLock<AdoptionFacts>,
    covered: std::sync::OnceLock<RecordSet>,
}

/// A set of `(seq or index, 16-byte hash)` pairs, as a sorted vector
/// (Round 39, R39-CB-5). These sets hold one entry per unkeyed or legacy
/// record a key adoption covers, for the life of the process: as a hash set
/// that measured 129 bytes per record (300,000 records: 37 MiB), so the
/// history a key was adopted over decided whether the server fitted its
/// memory limit. Sorted and shrunk it is 24 bytes per record, looked up by
/// binary search. The same set, the same answers.
#[derive(Debug, Default)]
pub(crate) struct RecordSet(Vec<(u64, [u8; 16])>);

impl RecordSet {
    fn from_unsorted(mut entries: Vec<(u64, [u8; 16])>) -> Self {
        entries.sort_unstable();
        entries.dedup();
        entries.shrink_to_fit();
        Self(entries)
    }

    pub(crate) fn contains(&self, entry: &(u64, [u8; 16])) -> bool {
        self.0.binary_search(entry).is_ok()
    }
}

impl std::fmt::Debug for TrailFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrailFacts").finish_non_exhaustive()
    }
}

/// What the key-adoption records whose MAC verifies under a held key say.
#[derive(Debug, Default)]
pub(crate) struct AdoptionFacts {
    /// The key ids they name as the key before them.
    pub vouched: std::collections::HashSet<String>,
    /// The legacy lines they list, as (index in its file, short hash), when
    /// the legacy lines on disk are what one of them lists (R37-2).
    pub legacy: RecordSet,
}

/// What a reader's gate knows before the first line of a file: where the
/// walk is (`start`, from the older files), the keys it checks MACs under,
/// and how to reach the whole trail for `TrailFacts`.
#[derive(Clone, Default)]
pub(crate) struct GateContext {
    pub start: Cursor,
    /// The keys whose MACs this reader checks; empty: none (corruption-
    /// evident only).
    pub keys: std::sync::Arc<Vec<AuditKey>>,
    pub facts: std::sync::Arc<TrailFacts>,
    /// The trail's files, oldest first (`None`: nothing is vouched or
    /// covered).
    pub trail_files: Option<std::sync::Arc<dyn Fn() -> Vec<PathBuf> + Send + Sync>>,
    /// The trail id of the trail's newest record — the writer's own, for
    /// the server's readers (Round 38): a version-2 record under any other
    /// id is never read, wherever it stands, the top of the oldest file
    /// included.
    pub pin: Option<[u8; TRAIL_ID_BYTES]>,
    /// Pass 1 of `TrailFacts::unkeyed`.
    pub(crate) tentative: bool,
}

impl std::fmt::Debug for GateContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateContext")
            .field("start", &self.start)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl GateContext {
    /// No key, and the chain began before the file or not.
    #[cfg(test)]
    pub(crate) fn keyless(chain_began: bool) -> Self {
        Self {
            start: Cursor {
                chain_began,
                ..Cursor::default()
            },
            ..Self::default()
        }
    }

    fn held(&self, id: &str) -> Option<&AuditKey> {
        self.keys.iter().find(|k| k.id() == id)
    }

    fn files(&self) -> Vec<PathBuf> {
        self.trail_files.as_ref().map(|f| f()).unwrap_or_default()
    }
}

impl TrailFacts {
    fn adoptions(&self, ctx: &GateContext) -> &AdoptionFacts {
        self.adoptions.get_or_init(|| {
            let files = ctx.files();
            let adoptions = checked_adoptions(&files, &ctx.keys);
            let vouched = adoptions
                .iter()
                .filter_map(|a| a.previous_key_id.clone())
                .collect();
            let mut legacy = Vec::new();
            let on_disk = legacy_prefix(&files);
            if !on_disk.is_empty() {
                let digests: Vec<LegacyFile> = on_disk.iter().map(|(d, _)| d.clone()).collect();
                let vouched_for = adoptions.iter().any(|a| {
                    a.legacy
                        .as_deref()
                        .is_some_and(|listed| legacy_matches(listed, &digests))
                });
                if vouched_for {
                    for (_, hashes) in &on_disk {
                        for (i, h) in hashes.iter().enumerate() {
                            legacy.push((i as u64, *h));
                        }
                    }
                }
            }
            AdoptionFacts {
                vouched,
                legacy: RecordSet::from_unsorted(legacy),
            }
        })
    }

    /// The records whose MAC this reader cannot check — unkeyed ones, and
    /// (Round 38, R37-13) ones under a vouched key it does not hold — that a
    /// checked key-adoption record covers, as (seq, first half of the hash):
    /// found by walking the trail once with those records admitted
    /// tentatively, until an adoption whose MAC verifies under a held key
    /// continues that walk (pass 1). A forgery the walk took in place of a
    /// written record keeps the walk from ever reaching the adoption, and
    /// then nothing before it is covered: the readers lose those records,
    /// and never read the forgery.
    ///
    /// The walk stops once nothing is pending and the chain is under a key
    /// this reader holds. A later span under a key it does not hold (a
    /// reader holding the first and third keys of three, but not the
    /// second) is then not covered: refused, never read unchecked.
    fn covered(&self, ctx: &GateContext) -> &RecordSet {
        self.covered.get_or_init(|| {
            let mut cursor = Cursor::default();
            let mut pending = Vec::new();
            let mut covered = Vec::new();
            for path in ctx.files() {
                let pass = GateContext {
                    start: cursor,
                    tentative: true,
                    ..ctx.clone()
                };
                let mut gate = RecordGate::new(&pass);
                gate.pending = pending;
                let _ = walk_file(&path, u64::MAX, &mut gate, |_, _, _| {});
                cursor = gate.cur;
                pending = gate.pending;
                if covered.is_empty() {
                    covered = gate.covered;
                } else {
                    covered.append(&mut gate.covered);
                }
                if pending.is_empty()
                    && cursor
                        .chain_key
                        .as_deref()
                        .is_some_and(|k| ctx.held(k).is_some())
                {
                    break;
                }
            }
            RecordSet::from_unsorted(covered)
        })
    }
}

/// The key-adoption records of `files` whose MAC verifies under one of
/// `keys`.
fn checked_adoptions(files: &[PathBuf], keys: &[AuditKey]) -> Vec<KeyAdoption> {
    let mut found = Vec::new();
    if keys.is_empty() {
        return found;
    }
    let marker = format!("\"{CONTROL_FIELD}\":\"{KEY_ADOPTION}\"");
    for path in files {
        let Ok(file) = File::open(path) else {
            continue;
        };
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        loop {
            match read_line_bounded(&mut reader, &mut line, MAX_LINE_BYTES) {
                Ok((_, LineEnd::Terminated)) => {}
                Ok((_, LineEnd::Oversized { terminated: true })) => continue,
                _ => break,
            }
            let record = line.as_slice();
            if !std::str::from_utf8(record).is_ok_and(|t| t.contains(&marker)) {
                continue;
            }
            let LineClass::Chained(c) = classify_line(record) else {
                continue;
            };
            let Some(Ok(a)) = c.adoption() else {
                continue;
            };
            let (Some(id), Some(mac)) = (&c.link.key_id, &c.link.mac) else {
                continue;
            };
            if keys
                .iter()
                .find(|k| k.id() == id)
                .is_some_and(|key| mac_verifies(key, mac, &c.hash))
            {
                found.push(a.clone());
            }
        }
    }
    found
}

fn mac_verifies(key: &AuditKey, mac: &str, hash: &[u8; 32]) -> bool {
    hex::decode(mac)
        .map(|m| constant_time_eq(&m, &key.mac_of(MAC_DOMAIN, hash)))
        .unwrap_or(false)
}

/// Feed every terminated line of the first `limit` bytes of `path` to
/// `gate`, calling `visit(offset, line, admitted)` for each. A final line
/// without its newline is never offered. A file that cannot be read offers
/// nothing. Returns the bytes read, a final line without its newline
/// included.
pub(crate) fn walk_file(
    path: &Path,
    limit: u64,
    gate: &mut RecordGate,
    mut visit: impl FnMut(u64, &[u8], bool),
) -> u64 {
    let Ok(file) = File::open(path) else {
        return 0;
    };
    let mut reader = BufReader::new(file.take(limit));
    let mut offset = 0u64;
    let mut line = Vec::new();
    loop {
        let (n, end) = match read_line_bounded(&mut reader, &mut line, MAX_LINE_BYTES) {
            Ok((_, LineEnd::Eof)) | Err(_) => break,
            Ok(r) => r,
        };
        let at = offset;
        offset += n;
        match end {
            LineEnd::Terminated => {
                let admitted = gate.admit(&line);
                visit(at, &line, admitted);
            }
            // Never read; it may carry a link (Round 38, T-15).
            LineEnd::Oversized { terminated: true } => {
                gate.refuse_oversized();
                visit(at, &[], false);
            }
            _ => break,
        }
    }
    offset
}

impl RecordGate {
    /// A gate for a file, given what is known before its first line.
    pub(crate) fn new(ctx: &GateContext) -> Self {
        Self {
            cur: ctx.start.clone(),
            ctx: ctx.clone(),
            legacy_in_file: 0,
            pending: Vec::new(),
            covered: Default::default(),
        }
    }

    /// Where the walk is after the lines judged so far.
    pub(crate) fn cursor(&self) -> &Cursor {
        &self.cur
    }

    /// A line longer than `MAX_LINE_BYTES`, read past unread (Round 38,
    /// T-15): never a record, and it may carry a link, so no legacy line
    /// after it is read.
    pub(crate) fn refuse_oversized(&mut self) {
        self.cur.chain_began = true;
    }

    /// A record whose MAC this reader cannot check — unkeyed, or under a
    /// vouched key — is read only when a checked key-adoption record covers
    /// it (`TrailFacts::covered`); in pass 1, tentatively.
    fn admit_if_covered(&mut self, c: &ChainedLine) -> bool {
        let mut half = [0u8; 16];
        half.copy_from_slice(&c.hash[..16]);
        let entry = (c.link.seq, half);
        if self.ctx.tentative {
            self.pending.push(entry);
            return true;
        }
        self.ctx.facts.covered(&self.ctx).contains(&entry)
    }

    /// Whether `line` (a terminated line, without its newline) is a record
    /// the readers may read. A control record that continues the walk
    /// moves it on and is not a record.
    pub(crate) fn admit(&mut self, line: &[u8]) -> bool {
        match classify_line(line) {
            LineClass::Chained(c) => {
                self.cur.chain_began = true;
                if !self.accept(&c) {
                    return false;
                }
                self.advance(&c);
                c.control.is_none()
            }
            LineClass::Legacy => {
                let index = self.legacy_in_file;
                self.legacy_in_file += 1;
                if self.cur.chain_began {
                    return false;
                }
                if self.ctx.keys.is_empty() {
                    return true;
                }
                self.ctx
                    .facts
                    .adoptions(&self.ctx)
                    .legacy
                    .contains(&(index, short_hash(line)))
            }
            LineClass::Invalid { chained, .. } => {
                self.cur.chain_began |= chained;
                false
            }
            LineClass::Blank => false,
        }
    }

    /// Whether a chained line continues the walk (see `RecordGate`).
    fn accept(&mut self, c: &ChainedLine) -> bool {
        if let Some(Err(_)) = &c.control {
            return false;
        }
        let prev = decode32(&c.link.prev);
        match self.cur.last {
            Some((seq, hash)) => {
                if c.link.seq != seq.saturating_add(1) || prev != Some(hash) {
                    return false;
                }
            }
            None => {
                if c.link.seq == 0 && prev != Some(GENESIS) {
                    return false;
                }
            }
        }
        let other_trail = match (self.cur.trail, c.trail) {
            (Some(t), Some(u)) => t != u,
            (Some(_), None) => return false,
            _ => false,
        } || matches!((self.ctx.pin, c.trail), (Some(pin), Some(t)) if pin != t);
        if other_trail {
            // Round 39 (R39-CB-1): noted when the line is genuine under a
            // key this reader holds, so a writer does not resume onto
            // whichever of two trails was appended last.
            if self.genuine_to_this_reader(c) {
                self.cur.other_trail = true;
            }
            return false;
        }
        let keyed_reader = !self.ctx.keys.is_empty();
        match (&c.link.key_id, &c.link.mac) {
            (None, None) => {
                if c.adoption().is_some() || self.cur.chain_key.is_some() {
                    return false;
                }
                if !keyed_reader {
                    return true;
                }
                self.admit_if_covered(c)
            }
            (Some(id), Some(mac)) => {
                if self.cur.retired.iter().any(|r| r == id) {
                    return false;
                }
                let checked = if keyed_reader {
                    match self.ctx.held(id) {
                        Some(key) => {
                            if !mac_verifies(key, mac, &c.hash) {
                                return false;
                            }
                            true
                        }
                        None => {
                            if !self.ctx.facts.adoptions(&self.ctx).vouched.contains(id) {
                                return false;
                            }
                            false
                        }
                    }
                } else {
                    false
                };
                let continues = match c.adoption() {
                    Some(Ok(a)) => {
                        if a.key_id != *id || a.previous_key_id != self.cur.chain_key {
                            return false;
                        }
                        if self.ctx.tentative && checked {
                            if self.covered.is_empty() {
                                // The common case, one adoption over the
                                // whole history: no second copy of it.
                                std::mem::swap(&mut self.covered, &mut self.pending);
                            } else {
                                self.covered.append(&mut self.pending);
                            }
                        }
                        true
                    }
                    Some(Err(_)) => false,
                    None => match &self.cur.chain_key {
                        None => true,
                        Some(current) if current == id => true,
                        // A key change with no adoption record: a rotation
                        // written before Round 34, accepted only before the
                        // first adoption record.
                        Some(current) => {
                            !self.cur.adopted
                                && (!keyed_reader || (checked && self.ctx.held(current).is_some()))
                        }
                    },
                };
                // Under a vouched key (Round 38, R37-13): only where a
                // checked adoption covers it.
                continues && (!keyed_reader || checked || self.admit_if_covered(c))
            }
            _ => false,
        }
    }

    /// Whether `c` is a record this reader would take as written by the
    /// trail's writer, its trail id aside: MAC'd under a key it holds, with
    /// the MAC verifying; for a reader without a key, any valid chained line
    /// (to it the trail is corruption-evident only).
    fn genuine_to_this_reader(&self, c: &ChainedLine) -> bool {
        if self.ctx.keys.is_empty() {
            return true;
        }
        match (&c.link.key_id, &c.link.mac) {
            (Some(id), Some(mac)) => self
                .ctx
                .held(id)
                .is_some_and(|key| mac_verifies(key, mac, &c.hash)),
            _ => false,
        }
    }

    /// Move the walk past an accepted chained line.
    fn advance(&mut self, c: &ChainedLine) {
        self.cur.last = Some((c.link.seq, c.hash));
        if c.trail.is_some() {
            self.cur.trail = c.trail;
        }
        if let Some(id) = &c.link.key_id {
            let previous = match c.adoption() {
                Some(Ok(a)) => {
                    self.cur.adopted = true;
                    a.previous_key_id.clone()
                }
                _ => self.cur.chain_key.clone(),
            };
            if let Some(p) = previous {
                if p != *id && !self.cur.retired.contains(&p) {
                    self.cur.retired.push(p);
                }
            }
            self.cur.chain_key = Some(id.clone());
        }
    }
}

fn decode32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// The newest line of a file that carries a chain link.
#[derive(Debug, Clone)]
pub(crate) enum Newest {
    /// `true`: it is the file's final line, without its newline.
    Valid(Box<ChainedLine>, bool),
    /// It carries a link and is not a valid chained record.
    Altered { seq: Option<u64>, reason: String },
}

/// The newest line of `path` that carries a chain link, read backwards from
/// its end. `None` when the file holds none (missing, empty, legacy only).
///
/// A final line without its newline counts only when it parses as JSON: a
/// whole record that lacks only its newline is the newest record, and any
/// other JSON is judged as a line. A torn write (not JSON) is passed over —
/// it was never acknowledged, and the writer names it in the next record it
/// appends.
pub(crate) fn newest_chained(path: &Path) -> std::io::Result<Option<Newest>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    // Read windows from the end, doubling, until a chained line is found or
    // the whole file has been read. A record is a few hundred bytes; the
    // first 64 KiB window answers for every trail Graphite writes. Past four
    // times the line bound (Round 38, T-15) the file is read forward, a line
    // at a time, instead: memory stays bounded whatever the file holds.
    let mut window: u64 = 64 * 1024;
    loop {
        if window > 4 * MAX_LINE_BYTES as u64 && window < len {
            return newest_chained_forward(file);
        }
        let start = len.saturating_sub(window);
        file.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::with_capacity((len - start) as usize);
        (&mut file).take(len - start).read_to_end(&mut buf)?;
        let mut lines: Vec<&[u8]> = buf.split(|b| *b == b'\n').collect();
        // The last piece is the file's unterminated tail (empty when the
        // file ends with a newline).
        let tail = lines.pop().unwrap_or_default();
        // The first piece of a window that does not start the file may be
        // the tail of a line cut by the window.
        if start > 0 && !lines.is_empty() {
            lines.remove(0);
        }
        let tail_is_json = !tail.is_empty()
            && tail.len() <= MAX_LINE_BYTES
            && serde_json::from_slice::<serde_json::Value>(tail).is_ok();
        let candidates = tail_is_json
            .then_some((tail, true))
            .into_iter()
            .chain(lines.into_iter().rev().map(|l| (l, false)));
        for (line, unterminated) in candidates {
            if line.len() > MAX_LINE_BYTES {
                return Ok(Some(oversized_newest()));
            }
            match classify_line(line) {
                LineClass::Chained(c) => return Ok(Some(Newest::Valid(c, unterminated))),
                LineClass::Invalid {
                    chained: true,
                    seq,
                    reason,
                    ..
                } => return Ok(Some(Newest::Altered { seq, reason })),
                _ => {}
            }
        }
        if start == 0 {
            return Ok(None);
        }
        window = window.saturating_mul(2);
    }
}

/// A line over the bound where the newest chained line is looked for: it
/// may carry a link, and it cannot be read, so the head is not known.
fn oversized_newest() -> Newest {
    Newest::Altered {
        seq: None,
        reason: format!(
            "a line longer than {MAX_LINE_BYTES} bytes, which no writer of this trail writes"
        ),
    }
}

/// `newest_chained` by one forward pass, a line at a time.
fn newest_chained_forward(file: File) -> std::io::Result<Option<Newest>> {
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(0))?;
    let mut line = Vec::new();
    let mut newest = None;
    loop {
        let (_, end) = read_line_bounded(&mut reader, &mut line, MAX_LINE_BYTES)?;
        match end {
            LineEnd::Eof => break,
            LineEnd::Oversized { .. } => newest = Some(oversized_newest()),
            LineEnd::Terminated | LineEnd::Unterminated => {
                let unterminated = end == LineEnd::Unterminated;
                if unterminated && serde_json::from_slice::<serde_json::Value>(&line).is_err() {
                    break;
                }
                match classify_line(&line) {
                    LineClass::Chained(c) => newest = Some(Newest::Valid(c, unterminated)),
                    LineClass::Invalid {
                        chained: true,
                        seq,
                        reason,
                        ..
                    } => newest = Some(Newest::Altered { seq, reason }),
                    _ => {}
                }
                if unterminated {
                    break;
                }
            }
        }
    }
    Ok(newest)
}

/// The trail id of the newest chained record of the trail (`newest_chained`
/// of the active file, else of the newest archive holding one): what the
/// readers pin (`GateContext::pin`). `None` for a version-1 head or none.
pub(crate) fn head_trail(
    active: &Path,
    archives_newest_first: &[PathBuf],
) -> Option<[u8; TRAIL_ID_BYTES]> {
    for file in std::iter::once(active).chain(archives_newest_first.iter().map(PathBuf::as_path)) {
        match newest_chained(file) {
            Ok(None) => continue,
            Ok(Some(Newest::Valid(c, _))) => return c.trail,
            _ => return None,
        }
    }
    None
}

/// The key id of the trail's newest chained record (`None`: unkeyed, or no
/// chained record). An error when that record is not a valid one.
pub(crate) fn head_key(
    active: &Path,
    archives_newest_first: &[PathBuf],
) -> Result<Option<String>, String> {
    for file in std::iter::once(active).chain(archives_newest_first.iter().map(PathBuf::as_path)) {
        match newest_chained(file) {
            Ok(None) => continue,
            Ok(Some(Newest::Valid(c, _))) => return Ok(c.link.key_id.clone()),
            Ok(Some(Newest::Altered { reason, .. })) => {
                return Err(format!(
                    "the newest chained audit record ({}) is not a valid record: {reason}",
                    file.display()
                ))
            }
            Err(e) => return Err(format!("reading {}: {e}", file.display())),
        }
    }
    Ok(None)
}

/// A key-adoption record the writer must append before anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdoptionPlan {
    pub previous_key_id: Option<String>,
    pub previous_key_checked: bool,
}

/// Where a writer resumes, and whether it must first adopt its key.
#[derive(Debug, Clone)]
pub(crate) struct Resume {
    pub head: ChainHead,
    pub adoption: Option<AdoptionPlan>,
}

/// Where the next record of the trail at `active` joins the chain: after the
/// newest chained record of the active file, else of the newest archive
/// that holds one, else at genesis.
///
/// Refused when that record is not a valid chained record, when its MAC is
/// under `key` and does not verify, and (Round 34) whenever continuing
/// would vouch for a head the writer cannot check:
///
/// - a key is configured and the head carries no MAC: MAC'ing on top of an
///   unkeyed history vouches for whatever it holds, including a keyed trail
///   rewritten with its MACs stripped. `adopt` (only `graphite audit
///   adopt-key`, an operator's explicit decision) resumes and plans a
///   key-adoption record;
/// - the head is MAC'd under a key id that is not the configured key's:
///   accepted when `previous` is that key and the head's MAC verifies under
///   it (a rotation; a key-adoption record is planned), or with `adopt` (a
///   lost key, recorded as not checked). A head under a key id nobody
///   supplies is what a rewrite under an invented key id looks like.
///
/// Round 38: `walked` is where the readers' walk of the whole trail ends
/// (with this writer's keys). Also refused:
///
/// - a head under a key the trail retired at a rotation (R37-4): rotation
///   is one-way, and a record under the old key after the adoption record
///   is one whoever still holds that key wrote;
/// - a head this writer can check (under one of its keys, or unkeyed with
///   no key configured) that is not where the walk ends (R37-5): a genuine
///   record copied to the end, or one from another trail. Continuing after
///   it would fork the chain;
/// - with a key configured, a trail that holds records without a chain
///   link and no chained record (R37-2): a chain keyed from genesis after
///   them would be indistinguishable from legacy lines inserted before it.
///   `adopt` writes a key-adoption record at genesis that lists them.
///
/// Round 39 (R39-CB-1): also refused, a trail whose walk refused a record of
/// another trail that is genuine under this writer's keys
/// (`Cursor::other_trail`): two trails under one key are on disk.
pub(crate) fn resume_head(
    active: &Path,
    archives_newest_first: &[PathBuf],
    key: Option<&AuditKey>,
    previous: Option<&AuditKey>,
    adopt: bool,
    walked: &Cursor,
    legacy_on_disk: bool,
) -> Result<Resume, String> {
    // Round 39 (R39-CB-1): records of two trails under this writer's keys.
    // The walk is pinned to the newest record's trail id, so a record of
    // another trail appended at the end made every genuine record "another
    // trail's" and itself the whole walk, which it then continued.
    if walked.other_trail {
        return Err(other_trail_refusal());
    }
    let files = std::iter::once(active.to_path_buf()).chain(archives_newest_first.iter().cloned());
    for file in files {
        let found =
            newest_chained(&file).map_err(|e| format!("reading {}: {e}", file.display()))?;
        let c = match found {
            None => continue,
            Some(Newest::Altered { seq, reason }) => {
                return Err(format!(
                    "the newest chained audit record ({}, seq {}) does not match its own hash: it was altered or corrupted ({reason}). Run `graphite audit verify` and move the trail aside before starting",
                    file.display(),
                    seq.map(|s| s.to_string()).unwrap_or_else(|| "?".into())
                ))
            }
            Some(Newest::Valid(c, unterminated)) => (c, unterminated),
        };
        let (c, unterminated) = c;
        let link = &c.link;
        let at = format!("{}, seq {}", file.display(), link.seq);
        if let Some(id) = &link.key_id {
            if walked.retired.iter().any(|r| r == id) {
                return Err(format!(
                    "the newest audit record ({at}) is MAC'd under key {id}, which this trail retired when it rotated to key {}: a key rotation is one-way, so a record under the retired key after the rotation was written by whoever still holds that key. Run `graphite audit verify`; unset {AUDIT_PREVIOUS_KEY_ENV} (docs/ops/keys.md)",
                    walked.chain_key.as_deref().unwrap_or("?")
                ));
            }
        }
        let checkable = match &link.key_id {
            Some(id) => key.is_some_and(|k| k.id() == id) || previous.is_some_and(|p| p.id() == id),
            None => key.is_none(),
        };
        if checkable {
            let continues = if unterminated {
                // A whole record that lacks only its newline: it must
                // continue where the walk (which never reads it) ends.
                match walked.last {
                    Some((seq, hash)) => {
                        link.seq == seq.saturating_add(1) && decode32(&link.prev) == Some(hash)
                    }
                    None => true,
                }
            } else {
                walked.last == Some((link.seq, c.hash))
            };
            if !continues {
                return Err(format!(
                    "the newest chained audit record ({at}) does not continue the chain the readers walk (it ends at {}): a genuine record copied to the end of the trail, or one from another trail. Continuing after it would fork the chain. Run `graphite audit verify`",
                    match walked.last {
                        Some((seq, _)) => format!("seq {seq}"),
                        None => "no record".into(),
                    }
                ));
            }
        }
        let head = ChainHead::after(link, c.hash);
        let mac_ok = |k: &AuditKey, mac: &str| {
            hex::decode(mac)
                .map(|m| constant_time_eq(&m, &k.mac_of(MAC_DOMAIN, &c.hash)))
                .unwrap_or(false)
        };
        let adopt_as = |previous_key_id: Option<String>, previous_key_checked: bool| Resume {
            head,
            adoption: Some(AdoptionPlan {
                previous_key_id,
                previous_key_checked,
            }),
        };
        return match (key, &link.key_id, &link.mac) {
            (None, Some(id), Some(_)) => Err(format!(
                "the audit trail is keyed (its newest record is MAC'd under key {id}) and no key is configured: set {AUDIT_KEY_ENV}. Continuing without a key would silently downgrade a tamper-evident trail"
            )),
            (None, None, None) => Ok(Resume {
                head,
                adoption: None,
            }),
            (Some(k), Some(id), Some(mac)) if id == k.id() => {
                if !mac_ok(k, mac) {
                    return Err(format!(
                        "the newest chained audit record ({at}) carries a MAC under key {id} that does not verify: it was altered. Run `graphite audit verify`"
                    ));
                }
                Ok(if adopt {
                    adopt_as(Some(id.clone()), true)
                } else {
                    Resume {
                        head,
                        adoption: None,
                    }
                })
            }
            (Some(k), Some(id), Some(mac)) => match previous.filter(|p| p.id() == id) {
                Some(p) if mac_ok(p, mac) => Ok(adopt_as(Some(id.clone()), true)),
                Some(_) => Err(format!(
                    "the newest chained audit record ({at}) carries a MAC under the previous key {id} that does not verify: it was altered. Run `graphite audit verify`"
                )),
                None if adopt => Ok(adopt_as(Some(id.clone()), false)),
                None => Err(format!(
                    "the newest audit record ({at}) is MAC'd under key {id}, not under the configured key {}. After a key rotation, set {AUDIT_PREVIOUS_KEY_ENV} to the previous key file for this start: the newest record is checked under it and a key-adoption record is written (docs/ops/keys.md). A key id nobody holds means the trail was rewritten: run `graphite audit verify`. A lost key: `graphite audit adopt-key`",
                    k.id()
                )),
            },
            (Some(k), None, None) => {
                if adopt {
                    Ok(adopt_as(None, false))
                } else {
                    Err(format!(
                        "the newest audit record ({at}) carries no MAC and a key ({}) is configured. MAC'ing on top of an unkeyed history would vouch for whatever it holds, a keyed trail rewritten with its MACs stripped included. If this trail was never keyed, check it (`graphite audit verify`) and run `graphite audit adopt-key` once with the server stopped (docs/ops/keys.md)",
                        k.id()
                    ))
                }
            }
            _ => Err(format!(
                "the newest chained audit record ({at}) has a MAC without a key id, or a key id without a MAC. Run `graphite audit verify`"
            )),
        };
    }
    if let (Some(k), true) = (key, legacy_on_disk) {
        if !adopt {
            return Err(format!(
                "the audit trail holds records without a chain link (written before Round 30) and no chained record, and a key ({}) is configured. A chain keyed from genesis after them could not be told from legacy lines inserted before it: check them (`graphite audit verify`) and run `graphite audit adopt-key` once with the server stopped; its key-adoption record lists them (docs/ops/keys.md)",
                k.id()
            ));
        }
        return Ok(Resume {
            head: ChainHead::genesis(),
            adoption: Some(AdoptionPlan {
                previous_key_id: None,
                previous_key_checked: false,
            }),
        });
    }
    Ok(Resume {
        head: ChainHead::genesis(),
        adoption: None,
    })
}

/// Why a writer, or a keyed read-only reader, refuses a trail holding
/// records of two trails (Round 39, R39-CB-1).
pub(crate) fn other_trail_refusal() -> String {
    "the audit trail holds records of another trail under the same key (a trail id other than the newest record's, MAC-verified): records copied in from another trail, at its start or its end. Which of the two is this trail cannot be told from the trail itself, so it is not resumed or read. Run `graphite audit verify`, which names the first record of another trail, and move the trail aside or restore it from a backup (docs/ops/keys.md)".to_string()
}

/// An exported statement of the chain's head, for anchoring outside the
/// writer's reach.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub kind: String,
    pub v: u8,
    /// The audit file name the trail is kept under (`audit.jsonl`).
    pub log: String,
    /// The newest record's position.
    pub seq: u64,
    /// The newest record's chain hash.
    pub hash: String,
    /// Chained records the export walked (informational: pruning lowers it).
    pub records: u64,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

impl Checkpoint {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.mac = None;
        let value = serde_json::to_value(&unsigned).unwrap_or(serde_json::Value::Null);
        let mut out = Vec::new();
        canonical_json(&value, &mut out);
        out
    }

    /// A checkpoint of `head`, MAC'd when a key is given.
    pub fn new(log: &str, seq: u64, hash: &str, records: u64, key: Option<&AuditKey>) -> Self {
        let mut cp = Checkpoint {
            kind: CHECKPOINT_KIND.to_string(),
            v: CHECKPOINT_VERSION,
            log: log.to_string(),
            seq,
            hash: hash.to_string(),
            records,
            created_at: super::now_utc_rfc3339(),
            key_id: key.map(|k| k.id().to_string()),
            mac: None,
        };
        if let Some(k) = key {
            cp.mac = Some(hex::encode(k.mac_of(CHECKPOINT_DOMAIN, &cp.signed_bytes())));
        }
        cp
    }

    /// Whether this checkpoint's MAC verifies: `Some(true/false)` when one
    /// of `keys` is the key it names, `None` when it has no MAC or none of
    /// `keys` is its key.
    pub fn mac_verifies(&self, keys: &[AuditKey]) -> Option<bool> {
        let (id, mac) = (self.key_id.as_ref()?, self.mac.as_ref()?);
        let key = keys.iter().find(|k| k.id() == id)?;
        let expected = key.mac_of(CHECKPOINT_DOMAIN, &self.signed_bytes());
        Some(
            hex::decode(mac)
                .map(|m| constant_time_eq(&m, &expected))
                .unwrap_or(false),
        )
    }
}

/// How much a verified trail proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    /// A break was found; `first_break` names it.
    Broken,
    /// Every chained record's MAC verified under a supplied key.
    TamperEvident,
    /// The chain is intact, but some records carry no MAC or one whose key
    /// was not supplied: proof against accident, not against a writer.
    CorruptionEvident,
    /// No chained record at all: a trail written before Round 30.
    LegacyUnchained,
}

/// Where the walk stopped.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ChainBreak {
    pub file: String,
    /// 1-based line number in that file.
    pub line: u64,
    /// Byte offset of the line in that file.
    pub offset: u64,
    /// The record's `seq`, when it had a readable link.
    pub seq: Option<u64>,
    pub reason: String,
}

/// What a supplied checkpoint established.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum CheckpointStatus {
    /// The record at the checkpoint's `seq` has the checkpoint's hash, and
    /// the trail continues to or past it.
    Confirmed,
    /// The checkpoint's own MAC did not verify under its key.
    ForgedCheckpoint,
    /// Keys were supplied, and the checkpoint carries no MAC or one under a
    /// key not among them (Round 34): whoever can write the trail can write
    /// such a checkpoint, so it confirms nothing. `key_id` is the key it
    /// names, if any.
    UnsignedCheckpoint { key_id: Option<String> },
    /// The record at the checkpoint's `seq` has a different hash.
    Rewritten,
    /// The trail ends before the checkpoint's `seq`: truncated, or restored
    /// from an older backup.
    Truncated { head_seq: Option<u64> },
    /// The records up to the checkpoint are no longer on disk (pruned), so
    /// it cannot be confirmed either way.
    NotOnDisk { first_seq: u64 },
}

/// The records of the trail under one key, in the order the chain reached
/// them (Round 34). A key the chain returns to opens a new range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeyRange {
    pub key_id: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub records: u64,
    /// Whether this key was among the keys supplied (its MACs were checked).
    pub supplied: bool,
    /// How the chain came to be under it: `first_keyed_record`,
    /// `adoption_checked` (a key-adoption record whose MAC verified),
    /// `adoption_unchecked` (one whose key was not supplied), or
    /// `switch_without_adoption` (a rotation written before key-adoption
    /// records, accepted because both keys were supplied and verified).
    pub introduced_by: String,
}

/// The result of walking a whole trail.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrailReport {
    pub integrity: Integrity,
    /// Files walked, oldest first (names only).
    pub files: Vec<String>,
    pub chained_records: u64,
    pub legacy_unchained_records: u64,
    /// Of `legacy_unchained_records`, those a checked key-adoption record
    /// lists (Round 38, R37-2).
    pub legacy_adopted: u64,
    /// Legacy records precede a chain keyed from its first record (seq 0)
    /// and no key-adoption record lists them: inserted (R37-2). This is the
    /// break `first_break` names (`graphite audit adopt-key` can still list
    /// them, once an operator has checked them).
    pub legacy_before_keyed_genesis: bool,
    /// The trail id of the version-2 records (Round 38), hex.
    pub trail_id: Option<String>,
    pub macs_verified: u64,
    /// MACs under a key that was not supplied.
    pub macs_unverified: u64,
    /// Of `macs_unverified`, those no checked key-adoption record after them
    /// covers through the hash chain (Round 38, T-12): records the keys
    /// supplied do not reach at all, such as a whole trail under another
    /// key. With keys supplied, any is exit 4; the rest (a lost key whose
    /// span a checked adoption closes) is exit 2.
    pub macs_not_covered: u64,
    /// Chained records with no MAC.
    pub unkeyed_records: u64,
    /// Of `unkeyed_records`, those a checked key-adoption record covers.
    pub unkeyed_adopted: u64,
    /// Key-adoption records in the chain.
    pub key_adoptions: u64,
    /// Whether any key was supplied to the walk.
    pub keys_supplied: bool,
    /// Lines that are not records and broke nothing (Round 34): torn writes
    /// a writer named in the next record it appended, and the active file's
    /// final line when it has no newline yet. No reader reads either. Any
    /// other line that is not a record is a break.
    pub unparseable_lines: u64,
    /// The `seq` of the oldest chained record on disk; above 0 when older
    /// archives were pruned.
    pub first_seq: Option<u64>,
    /// The oldest chained record on disk is above seq 0 and no prune record
    /// in the chain names it (Round 38, R37-14): the records before it were
    /// deleted, or pruned by a writer before prune records existed. This is
    /// the break `first_break` names (`graphite audit acknowledge-prune`
    /// records the prune, once an operator has checked the trail).
    pub pruned_without_record: bool,
    /// Prune records in the chain (written by the writer, or acknowledged).
    pub prune_records: u64,
    pub head_seq: Option<u64>,
    pub head_hash: Option<String>,
    /// The key the chain is under at its head (`None`: unkeyed).
    pub head_key_id: Option<String>,
    pub key_ids_seen: Vec<String>,
    pub key_ranges: Vec<KeyRange>,
    pub first_break: Option<ChainBreak>,
    /// When `first_break` is an unacknowledged tear: the break that stopped
    /// the walk after it, if one did — a trail broken by more than a tear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_break: Option<ChainBreak>,
    /// Lines that are not JSON, that no record names as a torn write the
    /// writer resumed past, and that no tear acknowledgement names: each a
    /// break (`graphite audit acknowledge-tear`, Round 34).
    pub unacknowledged_tears: Vec<TornLine>,
    /// Tears a tear acknowledgement names (counted in `unparseable_lines`).
    pub tears_acknowledged: u64,
    pub checkpoint: Option<CheckpointStatus>,
}

impl TrailReport {
    /// Whether nothing failed: no break, and any checkpoint confirmed.
    pub fn intact(&self) -> bool {
        self.first_break.is_none()
            && matches!(self.checkpoint, None | Some(CheckpointStatus::Confirmed))
    }

    /// Chained records with no MAC that no checked key-adoption record
    /// covers.
    pub fn unkeyed_not_adopted(&self) -> u64 {
        self.unkeyed_records.saturating_sub(self.unkeyed_adopted)
    }

    /// Legacy records no checked key-adoption record lists (Round 38).
    pub fn legacy_not_adopted(&self) -> u64 {
        self.legacy_unchained_records
            .saturating_sub(self.legacy_adopted)
    }

    /// What `graphite audit verify` exits with (docs/ops/keys.md):
    ///
    /// - 0: nothing failed — every link checked, every MAC under a supplied
    ///   key verified, and, when keys were supplied, every chained record
    ///   MAC'd under one of them or covered by a key-adoption record and any
    ///   checkpoint MAC'd under one of them;
    /// - 1: a break, or a checkpoint that does not hold;
    /// - 2: the walk could not prove what it was asked to — MACs under a key
    ///   not supplied, a trail with no chained record, a checkpoint whose
    ///   records were pruned;
    /// - 4 (Round 34): keys were supplied and something is not covered by
    ///   them — chained records with no MAC and no key-adoption record, a
    ///   checkpoint with no MAC or under a key not supplied, (Round 38,
    ///   R37-2) legacy records no checked key-adoption record lists, or
    ///   (Round 38, T-12) MACs under a key not supplied that no checked
    ///   key-adoption record after them covers (a trail under none of the
    ///   keys given exited 2, as if a key were merely missing).
    ///
    /// (3, a trail that could not be read, is decided by the caller.)
    pub fn exit_code(&self) -> i32 {
        if self.first_break.is_some() {
            return 1;
        }
        match &self.checkpoint {
            Some(CheckpointStatus::Rewritten)
            | Some(CheckpointStatus::Truncated { .. })
            | Some(CheckpointStatus::ForgedCheckpoint) => return 1,
            Some(CheckpointStatus::UnsignedCheckpoint { .. }) => return 4,
            _ => {}
        }
        if self.keys_supplied
            && (self.unkeyed_not_adopted() > 0
                || self.legacy_not_adopted() > 0
                || self.macs_not_covered > 0)
        {
            return 4;
        }
        if matches!(self.checkpoint, Some(CheckpointStatus::NotOnDisk { .. })) {
            return 2;
        }
        if self.integrity == Integrity::LegacyUnchained || self.macs_unverified > 0 {
            return 2;
        }
        0
    }

    /// Whether the keys supplied cover the head and everything before it,
    /// with nothing unproven but MACs under keys not supplied that checked
    /// key-adoption records close (a lost key, or an old key not passed):
    /// exit 0, or that exit 2 alone (Round 38, T-13). What `graphite audit
    /// checkpoint` requires before it signs a head.
    pub fn head_covered(&self) -> bool {
        match self.exit_code() {
            0 => true,
            2 => {
                self.keys_supplied
                    && self.macs_unverified > 0
                    && self.macs_not_covered == 0
                    && self.integrity != Integrity::LegacyUnchained
                    && matches!(self.checkpoint, None | Some(CheckpointStatus::Confirmed))
            }
            _ => false,
        }
    }
}

/// Walk every archive (oldest first) and then the active file, checking each
/// record against the chain — never against an index, which says only what
/// was written beside the trail. Each file is read up to its length when
/// the walk reaches it.
///
/// Every line is judged by `classify_line`, the grammar the readers apply
/// too (Round 34). A line that is not a record is a break, with two
/// exceptions, neither of which any reader reads: the active file's final
/// line while it has no newline (a write in flight, or torn by a crash),
/// and a torn write that the next record names (`TORN_TAIL_FIELD`) — the
/// writer saw it at its end and resumed past it. An archive is never
/// appended to, so an archive whose last line has no newline is a break.
///
/// `before_file(i)` is called before the walk opens its `i`-th file (a test
/// seam for a rotation during the walk).
pub(crate) fn verify_trail_with(
    active: &Path,
    archives_oldest_first: &[PathBuf],
    keys: &[AuditKey],
    checkpoint: Option<&Checkpoint>,
    before_file: &mut dyn FnMut(usize),
) -> std::io::Result<TrailReport> {
    let mut report = TrailReport {
        integrity: Integrity::LegacyUnchained,
        files: Vec::new(),
        chained_records: 0,
        legacy_unchained_records: 0,
        legacy_adopted: 0,
        legacy_before_keyed_genesis: false,
        trail_id: None,
        macs_verified: 0,
        macs_unverified: 0,
        macs_not_covered: 0,
        unkeyed_records: 0,
        unkeyed_adopted: 0,
        key_adoptions: 0,
        keys_supplied: !keys.is_empty(),
        unparseable_lines: 0,
        first_seq: None,
        pruned_without_record: false,
        prune_records: 0,
        head_seq: None,
        head_hash: None,
        head_key_id: None,
        key_ids_seen: Vec::new(),
        key_ranges: Vec::new(),
        first_break: None,
        other_break: None,
        unacknowledged_tears: Vec::new(),
        tears_acknowledged: 0,
        checkpoint: None,
    };
    // Torn writes no record after them named, each with the break it is
    // unless a tear acknowledgement names it (judged when the walk ends).
    let mut tears: Vec<(ChainBreak, TornLine)> = Vec::new();
    let mut acknowledgements: Vec<TearAcknowledgement> = Vec::new();
    let mut prev: Option<[u8; 32]> = None;
    let mut expected_seq: Option<u64> = None;
    // The key the chain is under (`None` until the first MAC'd record).
    let mut chain_key: Option<String> = None;
    // Unkeyed records not (yet) covered by a checked key-adoption record.
    let mut unkeyed_pending: u64 = 0;
    let mut checkpoint_hit: Option<bool> = None;
    let supplied = |id: &str| keys.iter().find(|k| k.id() == id);
    // Keys the chain moved away from, with the seq it moved at (R37-4).
    let mut retired: Vec<(String, u64)> = Vec::new();
    // The trail id of the version-2 records (R37-5).
    let mut trail: Option<[u8; TRAIL_ID_BYTES]> = None;
    // The legacy records of each file before the chain began (R37-2), the
    // first one's position, whether the oldest chained record is a MAC'd
    // seq 0, and whether a key-adoption record lists them.
    let mut legacy_files: Vec<LegacyFile> = Vec::new();
    let mut first_legacy: Option<ChainBreak> = None;
    let mut born_keyed = false;
    let mut legacy_listed = false;
    // MACs under a key not supplied that no checked adoption has covered
    // yet (T-12).
    let mut unverified_pending: u64 = 0;
    // The oldest chained record, where it is, and every place a prune record
    // says the trail may start (R37-14).
    let mut first_link: Option<(PruneBoundary, ChainBreak)> = None;
    let mut boundaries: Vec<PruneBoundary> = Vec::new();

    let mut files: Vec<PathBuf> = archives_oldest_first.to_vec();
    let has_active = active.exists();
    if has_active {
        files.push(active.to_path_buf());
    }
    let last_index = files.len().saturating_sub(1);
    'files: for (index, path) in files.iter().enumerate() {
        before_file(index);
        let is_active = has_active && index == last_index;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        report.files.push(name.clone());
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut reader = BufReader::new(file.take(len));
        let mut offset: u64 = 0;
        let mut line_no: u64 = 0;
        let mut buf: Vec<u8> = Vec::new();
        // A torn write, judged by the record after it.
        let mut pending: Option<(ChainBreak, TornLine)> = None;
        let mut legacy_digest = LegacyDigest::default();
        loop {
            let (n, end) = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES)?;
            if end == LineEnd::Eof {
                break;
            }
            line_no += 1;
            let at = offset;
            offset += n;
            let fail = |seq: Option<u64>, reason: String| ChainBreak {
                file: name.clone(),
                line: line_no,
                offset: at,
                seq,
                reason,
            };
            macro_rules! stop {
                ($seq:expr, $reason:expr) => {{
                    report.first_break = Some(fail($seq, $reason));
                    break 'files;
                }};
            }
            if let LineEnd::Oversized { .. } = end {
                // Round 38 (T-15): read past without being kept. Even named
                // as a torn write, or as the active file's line in flight:
                // no record and no crash leaves one this long.
                stop!(
                    None,
                    format!("a line longer than {MAX_LINE_BYTES} bytes: no writer of this trail writes one, and nothing reads it")
                );
            }
            let terminated = end == LineEnd::Terminated;
            let line: &[u8] = &buf[..];
            if !terminated {
                if line.iter().all(u8::is_ascii_whitespace) {
                    break;
                }
                if is_active {
                    // In flight, or torn at the very end: not judged, and
                    // never read. The writer names it in its next record.
                    report.unparseable_lines += 1;
                    break;
                }
                stop!(
                    None,
                    "an archive ends in a line without its newline: an archive is never appended to, so these bytes were added after it was rotated".into()
                );
            }
            let class = classify_line(line);
            if matches!(class, LineClass::Blank) {
                continue;
            }
            let names = match &class {
                LineClass::Chained(c) => c.torn_tail.clone(),
                _ => None,
            };
            match (pending.take(), names) {
                (Some((_, torn)), Some(named))
                    if named.offset == torn.offset
                        && named.length == torn.length
                        && named.sha256 == torn.sha256 =>
                {
                    report.unparseable_lines += 1
                }
                // Not named by the record after it: a break unless a tear
                // acknowledgement names it. The walk goes on — the record
                // after an honest tear continues the chain from the one
                // before it.
                (Some(tear), _) => tears.push(tear),
                (None, Some(named)) => stop!(
                    match &class {
                        LineClass::Chained(c) => Some(c.link.seq),
                        _ => None,
                    },
                    format!(
                        "the record names a torn line at byte {} that is not the line before it",
                        named.offset
                    )
                ),
                (None, None) => {}
            }
            let c = match class {
                LineClass::Blank => continue,
                LineClass::Invalid {
                    seq, reason, json, ..
                } => {
                    if json {
                        stop!(seq, reason);
                    }
                    // Not JSON at all: a torn write is exactly this. It is
                    // a break unless the next record names it.
                    let t = TornTail::of(at, line);
                    pending = Some((
                        fail(
                            seq,
                            format!("{reason}; no record after it names it as a torn write the writer resumed past, and no tear acknowledgement does (`graphite audit acknowledge-tear`)"),
                        ),
                        TornLine {
                            file: name.clone(),
                            line: line_no,
                            offset: t.offset,
                            length: t.length,
                            sha256: t.sha256,
                            after_seq: report.head_seq,
                        },
                    ));
                    continue;
                }
                LineClass::Legacy => {
                    if prev.is_some() {
                        stop!(
                            None,
                            "a record without a chain link after chained records: inserted, or written by a writer that bypassed the chain".into()
                        );
                    }
                    report.legacy_unchained_records += 1;
                    legacy_digest.add(line);
                    if first_legacy.is_none() {
                        first_legacy = Some(fail(
                            None,
                            "a record without a chain link before a chain keyed from its first record (seq 0), and no key-adoption record lists it: inserted. (An operator who has checked these records can list them with `graphite audit adopt-key`.)".into(),
                        ));
                    }
                    continue;
                }
                LineClass::Chained(c) => c,
            };
            let link = &c.link;
            let seq = Some(link.seq);
            let link_prev = decode32(&link.prev);
            match (prev, expected_seq) {
                (Some(p), Some(want)) => {
                    if link.seq != want {
                        stop!(
                            seq,
                            format!(
                                "sequence {} where {want} was expected: records were deleted, inserted or reordered",
                                link.seq
                            )
                        );
                    }
                    if link_prev != Some(p) {
                        stop!(
                            seq,
                            "`prev` is not the previous record's hash: the chain was spliced"
                                .into()
                        );
                    }
                }
                _ => {
                    // The oldest chained record on disk. At seq 0 it must
                    // start from genesis; above 0 the records before it were
                    // pruned and cannot be checked.
                    if link.seq == 0 && link_prev != Some(GENESIS) {
                        stop!(
                            seq,
                            "the first record (seq 0) does not start from genesis".into()
                        );
                    }
                    report.first_seq = Some(link.seq);
                    born_keyed = link.seq == 0 && link.mac.is_some();
                    if link.seq > 0 {
                        first_link = Some((
                            PruneBoundary {
                                first_seq: link.seq,
                                last_pruned_hash: link.prev.clone(),
                            },
                            fail(
                                seq,
                                format!(
                                    "the oldest record on disk is seq {} and no prune record in the chain names it: the records before it were deleted, or pruned by a writer before Round 38 (check the trail against an anchored checkpoint or a backup; then `graphite audit acknowledge-prune` records the prune)",
                                    link.seq
                                ),
                            ),
                        ));
                    }
                }
            }
            match (trail, c.trail) {
                (Some(t), Some(u)) if t != u => stop!(
                    seq,
                    format!(
                        "a record of another trail (trail id {}; this trail is {}): copied in from a trail under the same key",
                        hex::encode(u),
                        hex::encode(t)
                    )
                ),
                (Some(_), None) => stop!(
                    seq,
                    "a version-1 chain link after version-2 links: written by an older writer after a newer one, or copied in".into()
                ),
                _ => {}
            }
            if let Some(Err(e)) = &c.control {
                stop!(seq, format!("a malformed control record: {e}"));
            }
            match (&link.key_id, &link.mac) {
                (None, None) => {
                    if c.adoption().is_some() {
                        stop!(seq, "a key-adoption record without a MAC".into());
                    }
                    if chain_key.is_some() {
                        stop!(
                            seq,
                            "a record without a MAC after MAC'd records: the trail was downgraded or rewritten without the key".into()
                        );
                    }
                    report.unkeyed_records += 1;
                    unkeyed_pending += 1;
                }
                (Some(id), Some(mac)) => {
                    if !report.key_ids_seen.contains(id) {
                        report.key_ids_seen.push(id.clone());
                    }
                    if let Some((_, at_seq)) = retired.iter().find(|(k, _)| k == id) {
                        stop!(
                            seq,
                            format!(
                                "a record under key {id}, which the chain retired at seq {at_seq} when it moved to another key: a key rotation is one-way, so whoever still holds a retired key cannot extend the trail"
                            )
                        );
                    }
                    let checked = match supplied(id) {
                        Some(key) => {
                            let expected = key.mac_of(MAC_DOMAIN, &c.hash);
                            let ok = hex::decode(mac)
                                .map(|m| constant_time_eq(&m, &expected))
                                .unwrap_or(false);
                            if !ok {
                                stop!(
                                    seq,
                                    format!("MAC under key {id} does not verify: the record was rewritten by someone without the key")
                                );
                            }
                            report.macs_verified += 1;
                            true
                        }
                        None => {
                            report.macs_unverified += 1;
                            unverified_pending += 1;
                            false
                        }
                    };
                    let introduced: Option<&str> = match c.adoption() {
                        Some(Err(e)) => stop!(seq, format!("a malformed control record: {e}")),
                        Some(Ok(a)) => {
                            if a.key_id != *id {
                                stop!(
                                    seq,
                                    format!(
                                        "a key-adoption record names key {} but is MAC'd under key {id}",
                                        a.key_id
                                    )
                                );
                            }
                            if a.previous_key_id != chain_key {
                                stop!(
                                    seq,
                                    format!(
                                        "a key-adoption record names {} as the previous key, but the chain is under {}",
                                        a.previous_key_id.as_deref().unwrap_or("no key"),
                                        chain_key.as_deref().unwrap_or("no key")
                                    )
                                );
                            }
                            if let Some(listed) = &a.legacy {
                                let mut on_disk = legacy_files.clone();
                                let here = legacy_digest.finish();
                                if here.records > 0 {
                                    on_disk.push(here);
                                }
                                if !legacy_matches(listed, &on_disk) {
                                    stop!(
                                        seq,
                                        format!(
                                            "the key-adoption record lists {} legacy record(s) in {} file(s), and the records without a chain link before the chain are not those: one was inserted, altered or removed",
                                            listed.iter().map(|f| f.records).sum::<u64>(),
                                            listed.len()
                                        )
                                    );
                                }
                                legacy_listed = true;
                                if checked {
                                    report.legacy_adopted = report.legacy_unchained_records;
                                }
                            }
                            report.key_adoptions += 1;
                            if checked {
                                // Its MAC covers every record before it
                                // through the hash chain, from now on.
                                report.unkeyed_adopted += unkeyed_pending;
                                unkeyed_pending = 0;
                                unverified_pending = 0;
                                Some("adoption_checked")
                            } else {
                                Some("adoption_unchecked")
                            }
                        }
                        None => match &chain_key {
                            None => Some("first_keyed_record"),
                            Some(current) if current == id => None,
                            Some(current) => {
                                if report.key_adoptions > 0 {
                                    // Round 38 (R37-4): a key change with no
                                    // adoption record exists only in trails
                                    // rotated before Round 34, so only
                                    // before the first adoption record.
                                    stop!(
                                        seq,
                                        format!(
                                            "the key id changes from {current} to {id} at seq {} with no key-adoption record, after the trail's key-adoption records: every key change since Round 34 writes one",
                                            link.seq
                                        )
                                    );
                                }
                                if checked && supplied(current).is_some() {
                                    Some("switch_without_adoption")
                                } else {
                                    let missing = if supplied(current).is_none() {
                                        current
                                    } else {
                                        id
                                    };
                                    stop!(
                                        seq,
                                        format!(
                                            "the key id changes from {current} to {id} at seq {} with no key-adoption record, and {missing} is not among the keys supplied: a key id nobody holds (the trail was rewritten under it), or a rotation written before key-adoption records — verify with every key the trail was written under",
                                            link.seq
                                        )
                                    );
                                }
                            }
                        },
                    };
                    if let Some(how) = introduced {
                        if let Some(old) = chain_key.as_ref().filter(|old| *old != id) {
                            retired.push((old.clone(), link.seq));
                        }
                        chain_key = Some(id.clone());
                        report.key_ranges.push(KeyRange {
                            key_id: id.clone(),
                            first_seq: link.seq,
                            last_seq: link.seq,
                            records: 0,
                            supplied: supplied(id).is_some(),
                            introduced_by: how.to_string(),
                        });
                    }
                    if let Some(range) = report.key_ranges.last_mut() {
                        range.last_seq = link.seq;
                        range.records += 1;
                    }
                }
                _ => stop!(
                    seq,
                    "a MAC without a key id, or a key id without a MAC".into()
                ),
            }
            if let Some(Ok(Control::TearAcknowledgement(a))) = &c.control {
                acknowledgements.push(a.clone());
            }
            if let Some(Ok(Control::Prune(p))) = &c.control {
                report.prune_records += 1;
                boundaries.extend(p.retained.iter().cloned());
            }
            if let Some(cp) = checkpoint {
                if link.seq == cp.seq {
                    checkpoint_hit = Some(link.hash == cp.hash);
                }
            }
            report.chained_records += 1;
            if c.trail.is_some() {
                trail = c.trail;
            }
            prev = Some(c.hash);
            expected_seq = Some(link.seq.saturating_add(1));
            report.head_seq = Some(link.seq);
            report.head_hash = Some(link.hash.clone());
        }
        if let Some(tear) = pending.take() {
            tears.push(tear);
        }
        let here = legacy_digest.finish();
        if here.records > 0 {
            legacy_files.push(here);
        }
    }
    report.head_key_id = chain_key;
    report.trail_id = trail.map(hex::encode);
    // Every tear no record named must be acknowledged; the first that is not
    // is the break (it precedes any break that stopped the walk). Legacy
    // records before a chain keyed from seq 0 that nothing lists precede
    // everything (R37-2).
    report.macs_not_covered = unverified_pending;
    let real_break = report.first_break.take();
    if born_keyed && !legacy_listed {
        if let Some(b) = first_legacy {
            report.legacy_before_keyed_genesis = true;
            report.first_break = Some(b);
        }
    }
    // Round 38 (R37-14): a trail starting above seq 0 starts where a prune
    // record says it may, or records were deleted from its front. (Every
    // prune record the walk reached counts: a later one only ever names a
    // later start, and the start on disk only ever moves forward.)
    if let Some((first, at)) = first_link {
        if !boundaries.contains(&first) && report.first_break.is_none() {
            report.pruned_without_record = true;
            report.first_break = Some(at);
        }
    }
    for (brk, tear) in tears {
        if acknowledgements.iter().any(|a| a.names(&tear)) {
            report.tears_acknowledged += 1;
            report.unparseable_lines += 1;
        } else {
            if report.first_break.is_none() {
                report.first_break = Some(brk);
            }
            report.unacknowledged_tears.push(tear);
        }
    }
    match (&report.first_break, real_break) {
        (None, real) => report.first_break = real,
        (Some(_), real) => report.other_break = real,
    }

    report.integrity = if report.first_break.is_some() {
        Integrity::Broken
    } else if report.chained_records == 0 {
        Integrity::LegacyUnchained
    } else if report.macs_verified + report.unkeyed_adopted == report.chained_records
        && report.legacy_not_adopted() == 0
    {
        Integrity::TamperEvident
    } else {
        Integrity::CorruptionEvident
    };

    if let Some(cp) = checkpoint {
        let mac = cp.mac_verifies(keys);
        let status = if mac == Some(false) {
            CheckpointStatus::ForgedCheckpoint
        } else {
            match checkpoint_hit {
                Some(true) => CheckpointStatus::Confirmed,
                Some(false) => CheckpointStatus::Rewritten,
                None => match report.first_seq {
                    Some(first) if first > cp.seq => {
                        CheckpointStatus::NotOnDisk { first_seq: first }
                    }
                    _ => CheckpointStatus::Truncated {
                        head_seq: report.head_seq,
                    },
                },
            }
        };
        // Round 34 (R33-12): with keys supplied, a checkpoint that would
        // pass must be MAC'd under one of them — anyone who can write the
        // trail can write an unsigned one, or name a key nobody holds.
        report.checkpoint = Some(match status {
            CheckpointStatus::Confirmed | CheckpointStatus::NotOnDisk { .. }
                if !keys.is_empty() && mac.is_none() =>
            {
                CheckpointStatus::UnsignedCheckpoint {
                    key_id: cp.key_id.clone(),
                }
            }
            other => other,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2 and test case 6 (a key longer than the block).
    #[test]
    fn hmac_matches_rfc_4231() {
        let mac = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let key = [0xaau8; 131];
        let mac = hmac_sha256(
            &key,
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":{"z":[{"y":2,"x":1}],"c":"é"},"n":0.5}"#).unwrap();
        let mut out = Vec::new();
        canonical_json(&v, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"a":{"c":"é","z":[{"x":1,"y":2}]},"b":1,"n":0.5}"#
        );
    }

    #[test]
    fn a_short_key_is_refused_and_debug_never_prints_one() {
        assert!(AuditKey::from_bytes(&[7u8; 31]).is_err());
        let k = AuditKey::from_bytes(&[7u8; 32]).unwrap();
        let shown = format!("{k:?}");
        assert!(shown.contains("redacted") && !shown.contains("0707"));
        assert_eq!(k.id().len(), 16);
    }
}
