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
//! Records written before Round 30 carry no `chain`; they verify as
//! `legacy_unchained` and are never counted as tamper-evident.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The `chain.v` this module writes and verifies.
pub const CHAIN_VERSION: u8 = 1;

/// The environment variable naming the audit key file.
pub const AUDIT_KEY_ENV: &str = "GRAPHITE_AUDIT_KEY_FILE";

/// The environment variable naming the directory checkpoints are written to
/// at each rotation.
pub const AUDIT_ANCHOR_ENV: &str = "GRAPHITE_AUDIT_ANCHOR_DIR";

/// The JSON key a record's chain link is stored under.
pub const CHAIN_FIELD: &str = "chain";

/// The smallest key accepted, in bytes (HMAC-SHA256's output size).
pub const MIN_KEY_BYTES: usize = 32;

const LINK_DOMAIN: &[u8] = b"graphite-audit-chain-v1\0";
const MAC_DOMAIN: &[u8] = b"graphite-audit-mac-v1\0";
const CHECKPOINT_DOMAIN: &[u8] = b"graphite-audit-checkpoint-v1\0";
const KEY_ID_DOMAIN: &[u8] = b"graphite-audit-key-id-v1\0";

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
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// Equality that takes the same time wherever the inputs differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
}

impl ChainHead {
    pub fn genesis() -> Self {
        Self {
            next_seq: 0,
            prev: GENESIS,
            keyed: false,
        }
    }

    fn after(link: &ChainLink, hash: [u8; 32]) -> Self {
        Self {
            next_seq: link.seq.saturating_add(1),
            prev: hash,
            keyed: link.mac.is_some(),
        }
    }
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
    let hash = link_hash(&head.prev, head.next_seq, &canonical);
    let link = ChainLink {
        v: CHAIN_VERSION,
        seq: head.next_seq,
        prev: hex::encode(head.prev),
        hash: hex::encode(hash),
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
}

/// A line that is a chained record: its bytes are the canonical form of its
/// content and link, and its content recomputes to its own hash. Nothing
/// here says it links to the record before it or that its MAC verifies —
/// that takes the walk, and a key.
#[derive(Debug, Clone)]
pub(crate) struct ChainedLine {
    pub link: ChainLink,
    pub hash: [u8; 32],
    pub torn_tail: Option<TornTail>,
    /// `Some` for a control record: its key adoption, or why it is not one.
    pub control: Option<Result<KeyAdoption, String>>,
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
    if link.v != CHAIN_VERSION {
        return invalid(seq, format!("unknown chain version {}", link.v), true, true);
    }
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
    let hash = link_hash(&prev, link.seq, &content_bytes);
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
    let control = map.contains_key(CONTROL_FIELD).then(|| {
        serde_json::from_value::<KeyAdoption>(serde_json::Value::Object(map))
            .map_err(|e| e.to_string())
            .and_then(|a| {
                if a.audit_control == KEY_ADOPTION {
                    Ok(a)
                } else {
                    Err(format!("unknown control record `{}`", a.audit_control))
                }
            })
    });
    LineClass::Chained(Box::new(ChainedLine {
        link,
        hash,
        torn_tail,
        control,
    }))
}

/// What the readers apply to every line (Round 34): whether a line may be
/// read as a record. Every reader — the scans behind the dashboard, the
/// active and archive index builders, `find_verification`,
/// `count_verifications`, the lifecycle readers and every index read-back —
/// goes through this, and through nothing else.
///
/// A line is a record when it is a valid chained record (`classify_line`)
/// that is not a control record, or a legacy record before the chain began.
/// After the first line that carries a chain link, nothing else is ever a
/// record. A line without its newline is never offered to it: a final line
/// still in flight, or torn by a crash, is not part of the trail.
///
/// The gate does not check links or MACs — that takes the whole walk and a
/// key. What it guarantees is that the readers and `graphite audit verify`
/// read the same bytes the same way: every line a reader reads is one the
/// walk judged as that record, so a trail that verifies is exactly what the
/// readers see, and a line the readers cannot read is one the walk reports.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordGate {
    chain_began: bool,
}

impl RecordGate {
    /// A gate for a file, given whether the chain began in an older file.
    pub(crate) fn new(chain_began_before: bool) -> Self {
        Self {
            chain_began: chain_began_before,
        }
    }

    /// Whether a line carrying a chain link has been seen.
    pub(crate) fn chain_began(&self) -> bool {
        self.chain_began
    }

    /// Whether `line` (a terminated line, without its newline) is a record
    /// the readers may read.
    pub(crate) fn admit(&mut self, line: &[u8]) -> bool {
        match classify_line(line) {
            LineClass::Chained(c) => {
                self.chain_began = true;
                c.control.is_none()
            }
            LineClass::Legacy => !self.chain_began,
            LineClass::Invalid { chained, .. } => {
                // Even a broken link means the chain began: a forged line
                // never makes a legacy record after it readable.
                self.chain_began |= chained;
                false
            }
            LineClass::Blank => false,
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
    Valid(Box<ChainedLine>),
    /// It carries a link and is not a valid chained record.
    Altered {
        seq: Option<u64>,
        reason: String,
    },
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
    // first 64 KiB window answers for every trail Graphite writes.
    let mut window: u64 = 64 * 1024;
    loop {
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
        let tail_is_json =
            !tail.is_empty() && serde_json::from_slice::<serde_json::Value>(tail).is_ok();
        let candidates = tail_is_json
            .then_some(tail)
            .into_iter()
            .chain(lines.into_iter().rev());
        for line in candidates {
            match classify_line(line) {
                LineClass::Chained(c) => return Ok(Some(Newest::Valid(c))),
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

/// Whether `path` holds a line carrying a chain link.
pub(crate) fn holds_chain(path: &Path) -> std::io::Result<bool> {
    Ok(newest_chained(path)?.is_some())
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
pub(crate) fn resume_head(
    active: &Path,
    archives_newest_first: &[PathBuf],
    key: Option<&AuditKey>,
    previous: Option<&AuditKey>,
    adopt: bool,
) -> Result<Resume, String> {
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
            Some(Newest::Valid(c)) => c,
        };
        let link = &c.link;
        let at = format!("{}, seq {}", file.display(), link.seq);
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
    Ok(Resume {
        head: ChainHead::genesis(),
        adoption: None,
    })
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
            v: CHAIN_VERSION,
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
    pub macs_verified: u64,
    /// MACs under a key that was not supplied.
    pub macs_unverified: u64,
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
    pub head_seq: Option<u64>,
    pub head_hash: Option<String>,
    /// The key the chain is under at its head (`None`: unkeyed).
    pub head_key_id: Option<String>,
    pub key_ids_seen: Vec<String>,
    pub key_ranges: Vec<KeyRange>,
    pub first_break: Option<ChainBreak>,
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
    ///   them — chained records with no MAC and no key-adoption record, or a
    ///   checkpoint with no MAC or under a key not supplied.
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
        if self.keys_supplied && self.unkeyed_not_adopted() > 0 {
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
        macs_verified: 0,
        macs_unverified: 0,
        unkeyed_records: 0,
        unkeyed_adopted: 0,
        key_adoptions: 0,
        keys_supplied: !keys.is_empty(),
        unparseable_lines: 0,
        first_seq: None,
        head_seq: None,
        head_hash: None,
        head_key_id: None,
        key_ids_seen: Vec::new(),
        key_ranges: Vec::new(),
        first_break: None,
        checkpoint: None,
    };
    let mut prev: Option<[u8; 32]> = None;
    let mut expected_seq: Option<u64> = None;
    // The key the chain is under (`None` until the first MAC'd record).
    let mut chain_key: Option<String> = None;
    // Unkeyed records not (yet) covered by a checked key-adoption record.
    let mut unkeyed_pending: u64 = 0;
    let mut checkpoint_hit: Option<bool> = None;
    let supplied = |id: &str| keys.iter().find(|k| k.id() == id);

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
        let mut pending: Option<(ChainBreak, TornTail)> = None;
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)? as u64;
            if n == 0 {
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
            let terminated = buf.last() == Some(&b'\n');
            let line: &[u8] = if terminated {
                &buf[..buf.len() - 1]
            } else {
                &buf[..]
            };
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
                (Some((_, torn)), Some(named)) if named == torn => report.unparseable_lines += 1,
                (Some((brk, _)), _) => {
                    report.first_break = Some(brk);
                    break 'files;
                }
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
                    pending = Some((
                        fail(
                            seq,
                            format!("{reason}; no record after it names it as a torn write the writer resumed past"),
                        ),
                        TornTail::of(at, line),
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
                }
            }
            match (&link.key_id, &link.mac) {
                (None, None) => {
                    if c.control.is_some() {
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
                            false
                        }
                    };
                    let introduced: Option<&str> = match &c.control {
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
                            report.key_adoptions += 1;
                            if checked {
                                // Its MAC covers every record before it
                                // through the hash chain, from now on.
                                report.unkeyed_adopted += unkeyed_pending;
                                unkeyed_pending = 0;
                                Some("adoption_checked")
                            } else {
                                Some("adoption_unchecked")
                            }
                        }
                        None => match &chain_key {
                            None => Some("first_keyed_record"),
                            Some(current) if current == id => None,
                            Some(current) => {
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
            if let Some(cp) = checkpoint {
                if link.seq == cp.seq {
                    checkpoint_hit = Some(link.hash == cp.hash);
                }
            }
            report.chained_records += 1;
            prev = Some(c.hash);
            expected_seq = Some(link.seq.saturating_add(1));
            report.head_seq = Some(link.seq);
            report.head_hash = Some(link.hash.clone());
        }
        if let Some((brk, _)) = pending.take() {
            report.first_break = Some(brk);
            break 'files;
        }
    }
    report.head_key_id = chain_key;

    report.integrity = if report.first_break.is_some() {
        Integrity::Broken
    } else if report.chained_records == 0 {
        Integrity::LegacyUnchained
    } else if report.macs_verified + report.unkeyed_adopted == report.chained_records {
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
