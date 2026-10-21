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
        let text = std::fs::read_to_string(&resolved)
            .map_err(|e| format!("audit key file {}: {e}", path.display()))?;
        let material = hex::decode(text.trim()).map_err(|_| {
            format!(
                "audit key file {} must hold hex text (e.g. `openssl rand -hex 32`)",
                path.display()
            )
        })?;
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
    // Serializing a `Value` cannot fail.
    let line = serde_json::to_string(&serde_json::Value::Object(record)).unwrap_or_default();
    (line, next)
}

/// What one line of the trail is, as far as the chain is concerned.
enum LineKind {
    /// Not a JSON object: a torn write, or bytes that are not a record.
    Unparseable,
    /// A record written before the chain existed.
    Unchained,
    /// A record with a `chain` field that does not parse as a link.
    MalformedLink(String),
    /// A chained record: its link, and the hash its content recomputes to.
    Chained {
        link: ChainLink,
        recomputed: [u8; 32],
    },
}

fn classify(line: &[u8]) -> LineKind {
    let Ok(serde_json::Value::Object(mut map)) = serde_json::from_slice::<serde_json::Value>(line)
    else {
        return LineKind::Unparseable;
    };
    let Some(raw) = map.remove(CHAIN_FIELD) else {
        return LineKind::Unchained;
    };
    let link: ChainLink = match serde_json::from_value(raw) {
        Ok(l) => l,
        Err(e) => return LineKind::MalformedLink(e.to_string()),
    };
    let prev = match decode32(&link.prev) {
        Some(p) => p,
        None => return LineKind::MalformedLink("`prev` is not 32 hex bytes".into()),
    };
    let mut canonical = Vec::new();
    canonical_json(&serde_json::Value::Object(map), &mut canonical);
    LineKind::Chained {
        recomputed: link_hash(&prev, link.seq, &canonical),
        link,
    }
}

fn decode32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// The newest chained record of `path`, read backwards from its end: its
/// link and the hash its content recomputes to. `None` when the file holds
/// no chained record (missing, empty, or legacy only).
pub(crate) fn last_link_in(path: &Path) -> std::io::Result<Option<(ChainLink, [u8; 32])>> {
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
        // The first piece of a window that does not start the file may be
        // the tail of a line cut by the window.
        if start > 0 && !lines.is_empty() {
            lines.remove(0);
        }
        for line in lines.into_iter().rev() {
            if let LineKind::Chained { link, recomputed } = classify(line) {
                return Ok(Some((link, recomputed)));
            }
        }
        if start == 0 {
            return Ok(None);
        }
        window = window.saturating_mul(2);
    }
}

/// Where the next record of the trail at `audit_path` joins the chain:
/// after the newest chained record of the active file, else of the newest
/// archive that holds one, else at genesis. Refused when that record does
/// not recompute to its own hash, or when its MAC is under `key` and does
/// not verify — the trail would otherwise be extended past a record that
/// was altered, and `graphite audit verify` names it.
pub(crate) fn resume_head(
    active: &Path,
    archives_newest_first: &[PathBuf],
    key: Option<&AuditKey>,
) -> Result<ChainHead, String> {
    let files = std::iter::once(active.to_path_buf()).chain(archives_newest_first.iter().cloned());
    for file in files {
        let found = last_link_in(&file).map_err(|e| format!("reading {}: {e}", file.display()))?;
        let Some((link, recomputed)) = found else {
            continue;
        };
        let stored = decode32(&link.hash);
        if link.v != CHAIN_VERSION || stored != Some(recomputed) {
            return Err(format!(
                "the newest chained audit record ({}, seq {}) does not match its own hash: it was altered or corrupted. Run `graphite audit verify` and move the trail aside before starting",
                file.display(),
                link.seq
            ));
        }
        if let (Some(key), Some(id), Some(mac)) = (key, &link.key_id, &link.mac) {
            if id == key.id() {
                let expected = key.mac_of(MAC_DOMAIN, &recomputed);
                let ok = hex::decode(mac)
                    .map(|m| constant_time_eq(&m, &expected))
                    .unwrap_or(false);
                if !ok {
                    return Err(format!(
                        "the newest chained audit record ({}, seq {}) carries a MAC under key {id} that does not verify: it was altered. Run `graphite audit verify`",
                        file.display(),
                        link.seq
                    ));
                }
            }
        }
        if link.mac.is_some() && key.is_none() {
            return Err(format!(
                "the audit trail is keyed (its newest record is MAC'd under key {}) and no key is configured: set {AUDIT_KEY_ENV}. Continuing without a key would silently downgrade a tamper-evident trail",
                link.key_id.as_deref().unwrap_or("?")
            ));
        }
        return Ok(ChainHead::after(&link, recomputed));
    }
    Ok(ChainHead::genesis())
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
    /// The record at the checkpoint's `seq` has a different hash.
    Rewritten,
    /// The trail ends before the checkpoint's `seq`: truncated, or restored
    /// from an older backup.
    Truncated { head_seq: Option<u64> },
    /// The records up to the checkpoint are no longer on disk (pruned), so
    /// it cannot be confirmed either way.
    NotOnDisk { first_seq: u64 },
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
    /// Lines that are not JSON objects (a torn write after a crash). Never
    /// a break on their own: a deleted or altered record breaks the chain.
    pub unparseable_lines: u64,
    /// The `seq` of the oldest chained record on disk; above 0 when older
    /// archives were pruned.
    pub first_seq: Option<u64>,
    pub head_seq: Option<u64>,
    pub head_hash: Option<String>,
    pub key_ids_seen: Vec<String>,
    pub first_break: Option<ChainBreak>,
    pub checkpoint: Option<CheckpointStatus>,
}

impl TrailReport {
    /// Whether nothing failed: no break, and any checkpoint confirmed.
    pub fn intact(&self) -> bool {
        self.first_break.is_none()
            && matches!(self.checkpoint, None | Some(CheckpointStatus::Confirmed))
    }

    /// What `graphite audit verify` exits with: 0 when nothing failed, 1 on
    /// a break or a checkpoint that does not hold, 2 when the walk could not
    /// prove what it was asked to — MACs under a key that was not supplied,
    /// a trail with no chained record, a checkpoint whose records were
    /// pruned. (3, a trail that could not be read, is decided by the caller.)
    pub fn exit_code(&self) -> i32 {
        if self.first_break.is_some() {
            return 1;
        }
        match &self.checkpoint {
            Some(CheckpointStatus::Rewritten)
            | Some(CheckpointStatus::Truncated { .. })
            | Some(CheckpointStatus::ForgedCheckpoint) => return 1,
            Some(CheckpointStatus::NotOnDisk { .. }) => return 2,
            _ => {}
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
/// the walk reaches it; a final line without its newline is a write still
/// in flight and is not judged.
pub fn verify_trail(
    active: &Path,
    archives_oldest_first: &[PathBuf],
    keys: &[AuditKey],
    checkpoint: Option<&Checkpoint>,
) -> std::io::Result<TrailReport> {
    let mut report = TrailReport {
        integrity: Integrity::LegacyUnchained,
        files: Vec::new(),
        chained_records: 0,
        legacy_unchained_records: 0,
        macs_verified: 0,
        macs_unverified: 0,
        unkeyed_records: 0,
        unparseable_lines: 0,
        first_seq: None,
        head_seq: None,
        head_hash: None,
        key_ids_seen: Vec::new(),
        first_break: None,
        checkpoint: None,
    };
    let mut prev: Option<[u8; 32]> = None;
    let mut expected_seq: Option<u64> = None;
    let mut keyed_seen = false;
    let mut checkpoint_hit: Option<bool> = None;

    let mut files: Vec<PathBuf> = archives_oldest_first.to_vec();
    if active.exists() {
        files.push(active.to_path_buf());
    }
    'files: for path in &files {
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
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)? as u64;
            if n == 0 {
                break;
            }
            line_no += 1;
            let at = offset;
            offset += n;
            if buf.last() != Some(&b'\n') {
                // In flight, or torn at the very end: not judged.
                if !buf.iter().all(u8::is_ascii_whitespace) {
                    report.unparseable_lines += 1;
                }
                break;
            }
            let line = &buf[..buf.len() - 1];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let fail = |seq: Option<u64>, reason: String| ChainBreak {
                file: name.clone(),
                line: line_no,
                offset: at,
                seq,
                reason,
            };
            match classify(line) {
                LineKind::Unparseable => report.unparseable_lines += 1,
                LineKind::Unchained => {
                    if prev.is_some() {
                        report.first_break = Some(fail(
                            None,
                            "a record without a chain link after chained records: inserted, or written by a writer that bypassed the chain".into(),
                        ));
                        break 'files;
                    }
                    report.legacy_unchained_records += 1;
                }
                LineKind::MalformedLink(e) => {
                    report.first_break = Some(fail(None, format!("malformed chain link: {e}")));
                    break 'files;
                }
                LineKind::Chained { link, recomputed } => {
                    let seq = Some(link.seq);
                    if link.v != CHAIN_VERSION {
                        report.first_break =
                            Some(fail(seq, format!("unknown chain version {}", link.v)));
                        break 'files;
                    }
                    if decode32(&link.hash) != Some(recomputed) {
                        report.first_break = Some(fail(
                            seq,
                            "the record does not match its own chain hash: its content was altered"
                                .into(),
                        ));
                        break 'files;
                    }
                    let link_prev = decode32(&link.prev);
                    match (prev, expected_seq) {
                        (Some(p), Some(want)) => {
                            if link.seq != want {
                                report.first_break = Some(fail(
                                    seq,
                                    format!(
                                        "sequence {} where {want} was expected: records were deleted, inserted or reordered",
                                        link.seq
                                    ),
                                ));
                                break 'files;
                            }
                            if link_prev != Some(p) {
                                report.first_break = Some(fail(
                                    seq,
                                    "`prev` is not the previous record's hash: the chain was spliced".into(),
                                ));
                                break 'files;
                            }
                        }
                        _ => {
                            // The oldest chained record on disk. At seq 0 it
                            // must start from genesis; above 0 the records
                            // before it were pruned and cannot be checked.
                            if link.seq == 0 && link_prev != Some(GENESIS) {
                                report.first_break = Some(fail(
                                    seq,
                                    "the first record (seq 0) does not start from genesis".into(),
                                ));
                                break 'files;
                            }
                            report.first_seq = Some(link.seq);
                        }
                    }
                    match (&link.key_id, &link.mac) {
                        (Some(id), Some(mac)) => {
                            keyed_seen = true;
                            if !report.key_ids_seen.contains(id) {
                                report.key_ids_seen.push(id.clone());
                            }
                            match keys.iter().find(|k| k.id() == id) {
                                Some(key) => {
                                    let expected = key.mac_of(MAC_DOMAIN, &recomputed);
                                    let ok = hex::decode(mac)
                                        .map(|m| constant_time_eq(&m, &expected))
                                        .unwrap_or(false);
                                    if !ok {
                                        report.first_break = Some(fail(
                                            seq,
                                            format!("MAC under key {id} does not verify: the record was rewritten by someone without the key"),
                                        ));
                                        break 'files;
                                    }
                                    report.macs_verified += 1;
                                }
                                None => report.macs_unverified += 1,
                            }
                        }
                        (None, None) => {
                            if keyed_seen {
                                report.first_break = Some(fail(
                                    seq,
                                    "a record without a MAC after MAC'd records: the trail was downgraded or rewritten without the key".into(),
                                ));
                                break 'files;
                            }
                            report.unkeyed_records += 1;
                        }
                        _ => {
                            report.first_break = Some(fail(
                                seq,
                                "a MAC without a key id, or a key id without a MAC".into(),
                            ));
                            break 'files;
                        }
                    }
                    if let Some(cp) = checkpoint {
                        if link.seq == cp.seq {
                            checkpoint_hit = Some(link.hash == cp.hash);
                        }
                    }
                    report.chained_records += 1;
                    prev = Some(recomputed);
                    expected_seq = Some(link.seq.saturating_add(1));
                    report.head_seq = Some(link.seq);
                    report.head_hash = Some(link.hash.clone());
                }
            }
        }
    }

    report.integrity = if report.first_break.is_some() {
        Integrity::Broken
    } else if report.chained_records == 0 {
        Integrity::LegacyUnchained
    } else if report.macs_verified == report.chained_records {
        Integrity::TamperEvident
    } else {
        Integrity::CorruptionEvident
    };

    if let Some(cp) = checkpoint {
        report.checkpoint = Some(if cp.mac_verifies(keys) == Some(false) {
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
