//! A persisted index of one rotated audit archive (roadmap R-M11, Round 28).
//!
//! The active file's lookups were indexed in Rounds 9, 12 and 22; the
//! archives were not, so every L8 count with a chain digest and every lookup
//! of a key older than the last rotation was a pass over every archive,
//! however many there were. An archive is immutable once renamed, so its
//! index is computed once and kept beside it, in `<log>-index/`.
//!
//! The file is binary, fixed-width and sorted, and is searched by seeking
//! (about twenty 32-byte reads for a 64 MiB archive). Nothing of it is held
//! in memory: an archive's index holds an entry per key, and archives are
//! kept indefinitely by default, so loading them would grow memory with the
//! trail.
//!
//! An index is trusted only after it is checked against the archive it
//! describes, once per process:
//!
//! - its magic and version;
//! - its length, which the header's entry counts fix exactly;
//! - its trailer, over every byte before it: an HMAC-SHA256 under the
//!   trail's key, the reader's own (Round 38, R37-12), or a SHA-256 for a
//!   trail with no key;
//! - the archive's length and SHA-256, recorded in the header when the index
//!   was built.
//!
//! Anything else is rebuilt from one parse of the archive. A key's record is
//! still read back from the archive and matched before a lookup returns it.
//!
//! Layout (little-endian):
//!
//! ```text
//! header  80 bytes  magic[8] version:u32 trailer_kind:u32 archive_len:u64
//!                   archive_sha256[32] verifications:u64 lifecycle:u64
//!                   key_id[8]
//! verif   56 each   key_sha256[32] last_offset:u64 approved:u64 refused:u64
//! life    40 each   key_sha256[32] offset:u64       (sorted by key, offset)
//! trailer 32 bytes  kind 1: HMAC-SHA256 under the key `key_id` names, of
//!                   a domain tag and everything above; kind 0 (no key,
//!                   `key_id` zero): sha256 of everything above
//! ```
//!
//! Round 38 (R37-12): the trailer was always an unkeyed SHA-256, so an index
//! rewritten by whoever can write the data directory — one that omits a
//! transaction (the lookup then falls through to an older archive's
//! approval), points it at another record, or changes its counts — still
//! checked, over an archive whose own hash matched, and `verify` never reads
//! an index. A log with a key now trusts only an index MAC'd under that key
//! (the writer's key, or a read-only reader's configured key): any other
//! index is refused and the archive walked, and only a writer replaces it.
//! An index MAC'd under a key since rotated away is rebuilt once. A log
//! without a key trusts only an unkeyed index: to it the trail itself is
//! corruption-evident only.
//!
//! Keys are stored as the SHA-256 of the index key (`id:…`, `tx:…`, `ch:…`,
//! `lc:…`), so every entry has the same width. Two keys of one archive with
//! the same digest refuse the build, and the archive is scanned instead.
//!
//! Under a key the index is tamper-evident against anyone without the key
//! (the key lives outside the data directory). The archive it describes is
//! judged by the chain, as every reader judges it; the counts an index
//! answers with are additionally checked against the archive record they
//! point at (`super::index_entry_is_plausible`). Without a key an index is
//! corruption-evident only, as the trail is.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"GRAIDX\0\0";
/// The format version. A file with any other version is rebuilt.
///
/// 2 (Round 34): the same layout, built under the line grammar
/// (`chain::RecordGate`). A version-1 index may hold the offset of a line
/// the grammar refuses — a forged line the old parse indexed — so every
/// version-1 index is rebuilt rather than trusted.
///
/// 3 (Round 38, R37-5): built by the readers' walk, which admits a chained
/// line only where it continues the line before it. A version-2 index may
/// count, or point at, a genuine record copied to a new position, so it is
/// rebuilt rather than trusted.
///
/// 4 (Round 38, R37-12): the trailer is MAC'd under the trail's key, and the
/// header names the key. An unkeyed version-3 index is not trusted by a log
/// with a key; one without a key rebuilds it as version 4 once.
pub(super) const VERSION: u32 = 4;
const HEADER_LEN: u64 = 80;
/// `trailer_kind`: a SHA-256, for a log with no key.
const TRAILER_SHA256: u32 = 0;
/// `trailer_kind`: an HMAC-SHA256 under the key the header names.
const TRAILER_HMAC: u32 = 1;
const VERIFICATION_ENTRY: u64 = 56;
const LIFECYCLE_ENTRY: u64 = 40;
const TRAILER_LEN: u64 = 32;

/// Unique temporary names within the process, so two threads building the
/// same index never write one file.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// What an archive's index holds for one verification key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VerificationEntry {
    /// Byte offset of the LAST verification record under the key.
    pub last_offset: u64,
    pub approved: u64,
    pub refused: u64,
}

/// An index file checked against its archive.
///
/// Round 38 (R37-12): read through the handle it was checked through, and
/// only while that file is unchanged since (its length and change time). An
/// index is checked once per process, so a rewrite after the check — in
/// place, or by a rename over it — would otherwise be read unchecked by a
/// running server.
#[derive(Debug, Clone)]
pub(super) struct ArchiveIndex {
    file: std::sync::Arc<std::sync::Mutex<File>>,
    stamp: Stamp,
    /// The archive's length when the index was checked.
    pub archive_len: u64,
    verifications: u64,
    lifecycle: u64,
}

/// What changes whenever a file's bytes do: its length and change time
/// (`ctime`, which no caller can set back; the modification time elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    changed: (i64, i64),
}

fn stamp_of(file: &File) -> Option<Stamp> {
    let m = file.metadata().ok()?;
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        (m.ctime(), m.ctime_nsec())
    };
    #[cfg(not(unix))]
    let changed = {
        let t = m
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        (t.as_secs() as i64, i64::from(t.subsec_nanos()))
    };
    Some(Stamp {
        len: m.len(),
        changed,
    })
}

/// What an archive's index was built from: the archive's three indexes,
/// from `super::build_indexes`.
pub(super) struct IndexSource<'a> {
    pub last: &'a HashMap<String, u64>,
    pub counts: &'a HashMap<String, (usize, usize)>,
    pub lifecycle: &'a HashMap<String, Vec<u64>>,
}

fn key_digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// The SHA-256 and length of a whole file, streamed.
pub(super) fn file_sha256(path: &Path) -> std::io::Result<([u8; 32], u64)> {
    let mut reader = BufReader::with_capacity(1 << 16, File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut len = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hasher.finalize().into(), len))
}

/// The index file for `archive` inside `index_dir`.
pub(super) fn index_path(index_dir: &Path, archive: &Path) -> Option<PathBuf> {
    let name = archive.file_name()?.to_str()?;
    Some(index_dir.join(format!("{name}.idx")))
}

/// The trailer of an index whose bytes before it are fed to the result:
/// MAC'd under `key`, or a SHA-256 without one.
enum Trailer {
    Mac(super::chain::HmacSha256),
    Sha(Sha256),
}

impl Trailer {
    fn new(key: Option<&super::AuditKey>) -> Self {
        match key {
            Some(k) => Trailer::Mac(k.index_mac()),
            None => Trailer::Sha(Sha256::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Trailer::Mac(m) => m.update(bytes),
            Trailer::Sha(h) => h.update(bytes),
        }
    }

    fn finish(self) -> [u8; 32] {
        match self {
            Trailer::Mac(m) => m.finalize(),
            Trailer::Sha(h) => h.finalize().into(),
        }
    }
}

/// Write the index of an archive whose bytes hash to `archive_sha256`, MAC'd
/// under `key` (Round 38; unkeyed for a log without one), and return it
/// checked. Atomic: written to a temporary file, synced, then renamed over
/// the destination.
pub(super) fn write(
    index_path: &Path,
    archive_len: u64,
    archive_sha256: &[u8; 32],
    source: IndexSource<'_>,
    key: Option<&super::AuditKey>,
) -> std::io::Result<ArchiveIndex> {
    let invalid = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string());
    let mut verifications: Vec<([u8; 32], u64, u64, u64)> = Vec::with_capacity(source.counts.len());
    for (key, &(approved, refused)) in source.counts {
        let Some(&last) = source.last.get(key) else {
            return Err(invalid("a counted key has no offset"));
        };
        verifications.push((key_digest(key), last, approved as u64, refused as u64));
    }
    verifications.sort_unstable_by_key(|e| e.0);
    if verifications.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(invalid("two verification keys share a digest"));
    }
    let mut lifecycle: Vec<([u8; 32], u64)> = Vec::new();
    let mut lifecycle_digests: Vec<[u8; 32]> = Vec::with_capacity(source.lifecycle.len());
    for (key, offsets) in source.lifecycle {
        let digest = key_digest(key);
        lifecycle_digests.push(digest);
        lifecycle.extend(offsets.iter().map(|&o| (digest, o)));
    }
    lifecycle_digests.sort_unstable();
    if lifecycle_digests.windows(2).any(|w| w[0] == w[1]) {
        return Err(invalid("two lifecycle keys share a digest"));
    }
    lifecycle.sort_unstable();

    let mut bytes: Vec<u8> = Vec::with_capacity(
        (HEADER_LEN
            + verifications.len() as u64 * VERIFICATION_ENTRY
            + lifecycle.len() as u64 * LIFECYCLE_ENTRY
            + TRAILER_LEN) as usize,
    );
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    let kind = if key.is_some() {
        TRAILER_HMAC
    } else {
        TRAILER_SHA256
    };
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&archive_len.to_le_bytes());
    bytes.extend_from_slice(archive_sha256);
    bytes.extend_from_slice(&(verifications.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(lifecycle.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&key.map(|k| k.id_bytes()).unwrap_or([0u8; 8]));
    for (digest, last, approved, refused) in &verifications {
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(&last.to_le_bytes());
        bytes.extend_from_slice(&approved.to_le_bytes());
        bytes.extend_from_slice(&refused.to_le_bytes());
    }
    for (digest, offset) in &lifecycle {
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(&offset.to_le_bytes());
    }
    let mut trailer = Trailer::new(key);
    trailer.update(&bytes);
    let trailer = trailer.finish();
    bytes.extend_from_slice(&trailer);

    let dir = index_path
        .parent()
        .ok_or_else(|| invalid("index path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    let temp = index_path.with_extension(format!(
        "idx.tmp-{}-{}",
        std::process::id(),
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&temp, index_path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    super::sync_dir(index_path);
    // Read back and checked like any index: what is answered from is the
    // file as it is now, not the bytes this call meant to write.
    open_checked(index_path, archive_len, archive_sha256, key)
        .ok_or_else(|| invalid("the index written does not check"))
}

/// Open an index file and check it against the archive whose bytes hash to
/// `archive_sha256` and number `archive_len`. `None` for any disagreement:
/// a missing or short file, another magic or version, a length the header
/// does not account for, a trailer that is not the file's hash, or an index
/// of other archive bytes.
pub(super) fn open_checked(
    index_path: &Path,
    archive_len: u64,
    archive_sha256: &[u8; 32],
    key: Option<&super::AuditKey>,
) -> Option<ArchiveIndex> {
    let mut file = File::open(index_path).ok()?;
    let stamp = stamp_of(&file)?;
    let file_len = stamp.len;
    if file_len < HEADER_LEN + TRAILER_LEN {
        return None;
    }
    let mut header = [0u8; HEADER_LEN as usize];
    file.read_exact(&mut header).ok()?;
    if &header[0..8] != MAGIC {
        return None;
    }
    let u32_at = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
    let u64_at = |i: usize| u64::from_le_bytes(header[i..i + 8].try_into().unwrap());
    if u32_at(8) != VERSION || u64_at(16) != archive_len || &header[24..56] != archive_sha256 {
        return None;
    }
    // Under the reader's key, or unkeyed for a reader without one: nothing
    // else (R37-12).
    let (kind, key_id) = match key {
        Some(k) => (TRAILER_HMAC, k.id_bytes()),
        None => (TRAILER_SHA256, [0u8; 8]),
    };
    if u32_at(12) != kind || header[72..80] != key_id {
        return None;
    }
    let verifications = u64_at(56);
    let lifecycle = u64_at(64);
    let expected = verifications
        .checked_mul(VERIFICATION_ENTRY)?
        .checked_add(lifecycle.checked_mul(LIFECYCLE_ENTRY)?)?
        .checked_add(HEADER_LEN + TRAILER_LEN)?;
    if expected != file_len {
        return None;
    }
    let mut hasher = Trailer::new(key);
    hasher.update(&header);
    let mut remaining = file_len - HEADER_LEN - TRAILER_LEN;
    let mut buf = vec![0u8; 1 << 16];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        file.read_exact(&mut buf[..n]).ok()?;
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let mut trailer = [0u8; 32];
    file.read_exact(&mut trailer).ok()?;
    let computed = hasher.finish();
    if !super::chain::constant_time_eq(&computed, &trailer) {
        return None;
    }
    // Unchanged while it was read: what was checked is what is answered from.
    if stamp_of(&file)? != stamp {
        return None;
    }
    Some(ArchiveIndex {
        file: std::sync::Arc::new(std::sync::Mutex::new(file)),
        stamp,
        archive_len,
        verifications,
        lifecycle,
    })
}

impl ArchiveIndex {
    /// The first entry of a section whose key digest is not below `digest`.
    fn lower_bound(
        file: &mut File,
        base: u64,
        width: u64,
        count: u64,
        digest: &[u8; 32],
    ) -> std::io::Result<u64> {
        let (mut lo, mut hi) = (0u64, count);
        let mut probe = [0u8; 32];
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            file.seek(SeekFrom::Start(base + mid * width))?;
            file.read_exact(&mut probe)?;
            if probe < *digest {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// The checked handle, while the file is unchanged since it was checked;
    /// an error otherwise, which every caller answers by discarding the
    /// index and walking the archive.
    fn checked_file(&self) -> std::io::Result<std::sync::MutexGuard<'_, File>> {
        let file = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if stamp_of(&file) != Some(self.stamp) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the index file changed after it was checked",
            ));
        }
        Ok(file)
    }

    /// The archive's entry for a verification index key, if it has one.
    pub(super) fn verification(&self, key: &str) -> std::io::Result<Option<VerificationEntry>> {
        let digest = key_digest(key);
        let mut file = self.checked_file()?;
        let at = Self::lower_bound(
            &mut file,
            HEADER_LEN,
            VERIFICATION_ENTRY,
            self.verifications,
            &digest,
        )?;
        if at == self.verifications {
            return Ok(None);
        }
        let mut entry = [0u8; VERIFICATION_ENTRY as usize];
        file.seek(SeekFrom::Start(HEADER_LEN + at * VERIFICATION_ENTRY))?;
        file.read_exact(&mut entry)?;
        if entry[0..32] != digest {
            return Ok(None);
        }
        let u64_at = |i: usize| u64::from_le_bytes(entry[i..i + 8].try_into().unwrap());
        Ok(Some(VerificationEntry {
            last_offset: u64_at(32),
            approved: u64_at(40),
            refused: u64_at(48),
        }))
    }

    /// The offsets of the archive's lifecycle rows under a lifecycle index
    /// key, in file order.
    pub(super) fn lifecycle_offsets(&self, key: &str) -> std::io::Result<Vec<u64>> {
        let digest = key_digest(key);
        let base = HEADER_LEN + self.verifications * VERIFICATION_ENTRY;
        let mut file = self.checked_file()?;
        let mut at = Self::lower_bound(&mut file, base, LIFECYCLE_ENTRY, self.lifecycle, &digest)?;
        let mut offsets = Vec::new();
        let mut entry = [0u8; LIFECYCLE_ENTRY as usize];
        file.seek(SeekFrom::Start(base + at * LIFECYCLE_ENTRY))?;
        // Bounded twice: by the section, and by the per-key bound the
        // archive's lifecycle index was built under. `<`, not `<=`
        // (Round 29, audit 2026-10-20): `<=` read, and returned, one entry
        // past the bound.
        while at < self.lifecycle && offsets.len() < super::MAX_LIFECYCLE_HISTORY {
            file.read_exact(&mut entry)?;
            if entry[0..32] != digest {
                break;
            }
            offsets.push(u64::from_le_bytes(entry[32..40].try_into().unwrap()));
            at += 1;
        }
        Ok(offsets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_index(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "graphite-archive-index-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("audit.jsonl.1700000000000-000000.idx")
    }

    /// Round 29 (audit 2026-10-20): `lifecycle_offsets` stops at the
    /// per-key bound. Its loop condition was `<=`, which returned
    /// `MAX_LIFECYCLE_HISTORY + 1` offsets for a key with more entries.
    #[test]
    fn lifecycle_offsets_never_exceed_the_per_key_bound() {
        let path = temp_index("bound");
        let key = "lc:id:gr-1".to_string();
        let mut lifecycle = HashMap::new();
        lifecycle.insert(
            key.clone(),
            (0..(super::super::MAX_LIFECYCLE_HISTORY as u64 + 6))
                .map(|i| i * 100)
                .collect::<Vec<u64>>(),
        );
        let index = write(
            &path,
            1_000_000,
            &[7u8; 32],
            IndexSource {
                last: &HashMap::new(),
                counts: &HashMap::new(),
                lifecycle: &lifecycle,
            },
            None,
        )
        .unwrap();
        let offsets = index.lifecycle_offsets(&key).unwrap();
        assert_eq!(offsets.len(), super::super::MAX_LIFECYCLE_HISTORY);
        assert_eq!(offsets[0], 0);
        assert!(index.lifecycle_offsets("lc:id:other").unwrap().is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// An index checks only against the archive bytes it was built from,
    /// and a flipped byte anywhere in it fails its trailer.
    #[test]
    fn an_index_checks_against_its_archive_and_its_own_trailer() {
        let path = temp_index("check");
        let mut last = HashMap::new();
        let mut counts = HashMap::new();
        last.insert("id:gr-1".to_string(), 42u64);
        counts.insert("id:gr-1".to_string(), (1usize, 2usize));
        write(
            &path,
            500,
            &[1u8; 32],
            IndexSource {
                last: &last,
                counts: &counts,
                lifecycle: &HashMap::new(),
            },
            None,
        )
        .unwrap();
        let index = open_checked(&path, 500, &[1u8; 32], None).expect("checks");
        assert_eq!(
            index.verification("id:gr-1").unwrap(),
            Some(VerificationEntry {
                last_offset: 42,
                approved: 1,
                refused: 2
            })
        );
        assert_eq!(index.verification("id:gr-2").unwrap(), None);
        assert!(open_checked(&path, 501, &[1u8; 32], None).is_none());
        assert!(open_checked(&path, 500, &[2u8; 32], None).is_none());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN as usize + 40] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(open_checked(&path, 500, &[1u8; 32], None).is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Round 38 (R37-12): an index under a key is trusted only by a reader
    /// holding that key; an unkeyed index (anyone can write one) or one under
    /// another key is not; and an index rewritten after it was checked is
    /// not read.
    #[test]
    fn an_index_is_trusted_only_under_the_readers_key_and_only_as_checked() {
        let path = temp_index("keyed");
        let k = super::super::AuditKey::from_bytes(&[3u8; 32]).unwrap();
        let other = super::super::AuditKey::from_bytes(&[4u8; 32]).unwrap();
        let mut last = HashMap::new();
        let mut counts = HashMap::new();
        last.insert("id:gr-1".to_string(), 42u64);
        counts.insert("id:gr-1".to_string(), (1usize, 0usize));
        let no_rows = HashMap::new();
        let source = || IndexSource {
            last: &last,
            counts: &counts,
            lifecycle: &no_rows,
        };
        write(&path, 500, &[1u8; 32], source(), Some(&k)).unwrap();
        let index = open_checked(&path, 500, &[1u8; 32], Some(&k)).expect("checks under k");
        assert!(open_checked(&path, 500, &[1u8; 32], Some(&other)).is_none());
        assert!(open_checked(&path, 500, &[1u8; 32], None).is_none());
        // Rewritten in place after the check: the checked index stops
        // answering. (Past a timestamp tick: a filesystem with coarse
        // timestamps keeps one change time for a few milliseconds.)
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN as usize + 40] ^= 1;
        {
            use std::io::Write;
            let mut f = OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all(&bytes).unwrap();
        }
        assert!(index.verification("id:gr-1").is_err());
        // An unkeyed index of the same entries: not trusted under k.
        write(&path, 500, &[1u8; 32], source(), None).unwrap();
        assert!(open_checked(&path, 500, &[1u8; 32], Some(&k)).is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
