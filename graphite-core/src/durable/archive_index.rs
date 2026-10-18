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
//! - its trailing SHA-256, over every byte before it;
//! - the archive's length and SHA-256, recorded in the header when the index
//!   was built.
//!
//! Anything else is rebuilt from one parse of the archive. A key's record is
//! still read back from the archive and matched before a lookup returns it.
//!
//! Layout (little-endian):
//!
//! ```text
//! header  72 bytes  magic[8] version:u32 reserved:u32 archive_len:u64
//!                   archive_sha256[32] verifications:u64 lifecycle:u64
//! verif   56 each   key_sha256[32] last_offset:u64 approved:u64 refused:u64
//! life    40 each   key_sha256[32] offset:u64       (sorted by key, offset)
//! trailer 32 bytes  sha256 of everything above
//! ```
//!
//! Keys are stored as the SHA-256 of the index key (`id:…`, `tx:…`, `ch:…`,
//! `lc:…`), so every entry has the same width. Two keys of one archive with
//! the same digest refuse the build, and the archive is scanned instead.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"GRAIDX\0\0";
/// The format version. A file with any other version is rebuilt.
pub(super) const VERSION: u32 = 1;
const HEADER_LEN: u64 = 72;
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
#[derive(Debug, Clone)]
pub(super) struct ArchiveIndex {
    path: PathBuf,
    /// The archive's length when the index was checked.
    pub archive_len: u64,
    verifications: u64,
    lifecycle: u64,
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

/// Write the index of an archive whose bytes hash to `archive_sha256`, and
/// return it checked. Atomic: written to a temporary file, synced, then
/// renamed over the destination.
pub(super) fn write(
    index_path: &Path,
    archive_len: u64,
    archive_sha256: &[u8; 32],
    source: IndexSource<'_>,
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
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&archive_len.to_le_bytes());
    bytes.extend_from_slice(archive_sha256);
    bytes.extend_from_slice(&(verifications.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(lifecycle.len() as u64).to_le_bytes());
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
    let trailer: [u8; 32] = Sha256::digest(&bytes).into();
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
    Ok(ArchiveIndex {
        path: index_path.to_path_buf(),
        archive_len,
        verifications: verifications.len() as u64,
        lifecycle: lifecycle.len() as u64,
    })
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
) -> Option<ArchiveIndex> {
    let mut file = File::open(index_path).ok()?;
    let file_len = file.metadata().ok()?.len();
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
    let verifications = u64_at(56);
    let lifecycle = u64_at(64);
    let expected = verifications
        .checked_mul(VERIFICATION_ENTRY)?
        .checked_add(lifecycle.checked_mul(LIFECYCLE_ENTRY)?)?
        .checked_add(HEADER_LEN + TRAILER_LEN)?;
    if expected != file_len {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(header);
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
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != trailer {
        return None;
    }
    Some(ArchiveIndex {
        path: index_path.to_path_buf(),
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

    /// The archive's entry for a verification index key, if it has one.
    pub(super) fn verification(&self, key: &str) -> std::io::Result<Option<VerificationEntry>> {
        let digest = key_digest(key);
        let mut file = File::open(&self.path)?;
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
        let mut file = File::open(&self.path)?;
        let mut at = Self::lower_bound(&mut file, base, LIFECYCLE_ENTRY, self.lifecycle, &digest)?;
        let mut offsets = Vec::new();
        let mut entry = [0u8; LIFECYCLE_ENTRY as usize];
        file.seek(SeekFrom::Start(base + at * LIFECYCLE_ENTRY))?;
        // Bounded twice: by the section, and by the per-key bound the
        // archive's lifecycle index was built under.
        while at < self.lifecycle && offsets.len() <= super::MAX_LIFECYCLE_HISTORY {
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
