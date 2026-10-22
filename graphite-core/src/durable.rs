//! Durability — audit trail persistence for verification results.
//!
//! The semantic-graph/baseline snapshot is handled inside
//! [`crate::verification::GraphiteCore::with_data_dir`]; this module owns the
//! append-only JSONL audit log that the HTTP server writes after every
//! verification. One JSON object per line, synced to the storage device per
//! write (`sync_data`, not `flush`) so a crash — of the process OR the
//! machine — loses at most the in-flight request.
//!
//! The read side sees the WHOLE trail: every rotated archive plus the active
//! file, in order. Until 2026-09-12 it opened only the active file, so the
//! moment a rotation happened the dashboard totals dropped to zero and L8
//! reconciliation forgot every verdict older than the active file — including
//! blocked ones, which are exactly the ones `BlockedButExecuted` exists to
//! catch.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

mod archive_index;
use archive_index::ArchiveIndex;
mod chain;
pub use chain::{
    AuditKey, ChainBreak, ChainLink, Checkpoint, CheckpointStatus, Integrity, TrailReport,
    AUDIT_ANCHOR_ENV, AUDIT_KEY_ENV, CHAIN_FIELD,
};

/// Default size at which the ACTIVE audit file is rotated (64 MiB).
///
/// Rotation exists for two reasons found by the 2026-09-05 production audit:
/// the log grew without bound (disk exhaustion on any long-running
/// deployment), and the dashboard endpoints do a full forward scan of it on
/// every poll, so read cost grew linearly forever. Bounding the ACTIVE file
/// bounds both.
pub const DEFAULT_ROTATE_BYTES: u64 = 64 * 1024 * 1024;

/// Append-only audit log of verification results.
///
/// `Clone` shares the same underlying file (used inside axum State).
///
/// ROTATION AND RETENTION (P9): the audit trail is append-only and rotation
/// never rewrites or edits a record — when the active file passes
/// `rotate_bytes` it is RENAMED to `audit.jsonl.<stamp>-<seq>` and a fresh
/// active file is started. The stamp is the wall clock in milliseconds,
/// raised when needed so that it is above every archive already on disk
/// (`next_archive_path`); archives are ordered by it. Archives are retained indefinitely by default
/// (`max_archives == 0`), so the complete trail survives; an operator who
/// needs a hard disk bound sets `GRAPHITE_AUDIT_MAX_ARCHIVES` and accepts
/// that the oldest archives are pruned. Deleting audit history is therefore
/// always an explicit operator decision, never something Graphite does on its
/// own initiative.
#[derive(Debug, Clone)]
pub struct AuditLog {
    pub(crate) file: std::sync::Arc<Mutex<File>>,
    /// The log's path, kept so the read path (`read_all`) can re-open the
    /// file for reading without disturbing the append handle.
    path: Arc<PathBuf>,
    /// Rotate the active file once it exceeds this many bytes (0 = never).
    rotate_bytes: u64,
    /// Archives to keep (0 = keep all — the default, P9-preserving).
    max_archives: usize,
    /// Health counters. Audit writes are deliberately non-fatal (a failing
    /// audit disk must not take down verification), which previously meant a
    /// silent failure mode: nothing recorded, nothing surfaced. These are
    /// exported via /health and /metrics so an operator can alert on them.
    writes_ok: Arc<AtomicU64>,
    writes_failed: Arc<AtomicU64>,
    /// Whether the active file may end in a partial line — a write that
    /// failed part-way, or a file found at open without a trailing newline
    /// (Round 19, F-19-23). The next append starts with a newline so its
    /// record is never joined onto the fragment, where it would parse as
    /// neither and be lost to every lookup after a restart.
    torn_tail: Arc<std::sync::atomic::AtomicBool>,
    /// Monotonic rotation counter, appended to the archive name.
    ///
    /// The archive name was `audit.jsonl.<unix-millis>` alone. Rotations that
    /// landed in the SAME millisecond produced the SAME name, and
    /// `fs::rename` replaces an existing destination on every platform — so
    /// the previous archive was silently destroyed and its records with it.
    /// Whether that happens is pure timing: on a slow filesystem each
    /// rotation takes milliseconds and names never collide, while on a fast
    /// one dozens land in a single millisecond. That is exactly why it passed
    /// on a Windows dev machine (~4ms per rotation, measured) and failed in
    /// Linux CI.
    rotation_seq: Arc<AtomicU64>,
    /// The stamp the last archive name of this process was given.
    ///
    /// Round 29 (audit 2026-10-20, audit trail): the stamp was the wall
    /// clock alone, and archives were ordered by it, so a clock stepped
    /// back (NTP correction, a VM restored from a snapshot) named the next
    /// archive OLDER than the ones before it — pruning then deleted the
    /// newest archive and newest-first lookups read history in the wrong
    /// order. A stamp is now `max(now, newest archive's stamp + 1, this
    /// process's last stamp + 1)`: strictly increasing whatever the clock
    /// does, and still the wall clock whenever the clock is sane.
    last_stamp: Arc<Mutex<Option<u128>>>,
    /// Rotations that completed (rename + fresh active file).
    rotations_ok: Arc<AtomicU64>,
    /// `id:<audit_trail_id>` / `tx:<transaction_sha256>` / `ch:<content_hash>`
    /// → byte offset of the LAST verification record under that key in the
    /// ACTIVE file. Built by one scan at open, maintained on
    /// every append under the file lock, cleared when the active file
    /// rotates. What makes `last_verification_for` — the join L8 and every
    /// lifecycle event perform — a seek and one line instead of a scan of
    /// the whole active file (Round 9; measured at 953 ms per lookup over
    /// a 64 MB file, once per `/verify/execution` and per `/audit/event`,
    /// both caller-driven; 0.5 ms indexed).
    active_index: Arc<Mutex<HashMap<String, u64>>>,
    /// `lc:id:<audit_trail_id>` / `lc:tx:<transaction_sha256>` /
    /// `lc:sig:<signature>` → byte offsets of every lifecycle row under that
    /// key in the ACTIVE file, in file order, at most
    /// `MAX_LIFECYCLE_HISTORY` each. What lets `/audit/event` see the rows
    /// already on record for the transaction it is about — a submission
    /// already reported, a different signature already attached — without
    /// scanning the file (Round 12). Built at open, maintained on append,
    /// cleared on rotation like `active_index`.
    lifecycle_index: Arc<Mutex<HashMap<String, Vec<u64>>>>,
    /// How many verification records of the ACTIVE file each index key has,
    /// by verdict, and how many bytes of the file that accounts for. What
    /// lets `count_verifications` — run by every L8 reconciliation with a
    /// chain digest — answer for the active file without scanning it.
    /// Built at open, maintained on append, reset on rotation, and trusted
    /// only while it accounts for exactly the file's current length.
    active_counts: Arc<Mutex<ActiveCounts>>,
    /// Times `count_verifications` had to recount the active file because
    /// the counts did not account for it. A structural witness for tests:
    /// an indexed count leaves it unchanged.
    active_count_scans: Arc<AtomicU64>,
    /// Times `find_verification` scanned the active file because an indexed
    /// offset did not read back as its record. The same kind of witness for
    /// the lookup: an indexed hit or miss leaves it unchanged.
    active_lookup_scans: Arc<AtomicU64>,
    /// Rotations that could not happen. The record is still appended — an
    /// oversized log is strictly better than a dropped audit trail — but the
    /// failure used to be invisible, and it is retried on every subsequent
    /// append, so an operator saw only a file that never stopped growing.
    /// The realistic cause is another process holding the active file
    /// without delete-sharing (a log shipper, a scanner, `Get-Content -Wait`)
    /// or a read-only directory.
    rotations_failed: Arc<AtomicU64>,
    /// When the active file last rotated. Round 17 (F-15-09): a lifecycle
    /// that straddles a rotation has rows on both sides; the newest archive
    /// is merged into `lifecycle_history` while the rotation is recent
    /// enough for a lifecycle to have crossed it (`ROTATION_STRADDLE_WINDOW`),
    /// instead of only when the active file holds no row at all.
    last_rotation: Arc<Mutex<Option<std::time::Instant>>>,
    /// Per-archive statistics, computed once per archive.
    ///
    /// An archive is immutable by construction — rotation renames and never
    /// rewrites, and nothing appends to a renamed file — so its record counts
    /// are fixed the moment it exists. Caching them is what lets the read
    /// side account for the whole trail without rescanning every archive on
    /// every dashboard poll, which would reintroduce the unbounded read cost
    /// rotation was introduced to remove. Entries are validated by file
    /// length and dropped when the archive is pruned.
    archive_stats: Arc<Mutex<HashMap<PathBuf, ArchiveStats>>>,
    /// Each archive's persisted index (R-M11, Round 28), once checked
    /// against the archive in this process, or the fact that it cannot be
    /// had (an unwritable index directory, two keys with one digest), so a
    /// build is not retried on every lookup. Holds no entries of the index:
    /// those are read from disk by seeking (`archive_index.rs`).
    archive_indexes: Arc<Mutex<HashMap<PathBuf, IndexState>>>,
    /// Held while an archive's index is checked or built, so two lookups
    /// never build the same index at once.
    index_build: Arc<Mutex<()>>,
    /// Archives parsed to build their index. A structural witness for
    /// tests: once an archive is indexed, no lookup moves it.
    archive_index_builds: Arc<AtomicU64>,
    /// Archives passed over line by line by a lookup, a count or a
    /// lifecycle history, because no checked index could answer. The same
    /// kind of witness.
    archive_scans: Arc<AtomicU64>,
    /// Background index jobs not yet finished: the rotated archive's index
    /// written from the active file's indexes, the start-up check of every
    /// archive, and the sweep after pruning.
    index_jobs: Arc<AtomicU64>,
    /// Where the active file's acknowledged bytes end, while bytes after
    /// that point could not be removed; `NO_UNACKNOWLEDGED_BYTES` otherwise.
    ///
    /// Round 29 (audit 2026-10-20, audit trail): an append whose write or
    /// device sync failed was reported as not recorded, but whatever had
    /// landed stayed in the file — often the complete line — and after a
    /// restart it was indexed and counted as a verdict Graphite had refused
    /// to stand behind. A failed append now truncates the file back to its
    /// length before the append. If even that fails, the boundary is kept
    /// here: every reader of the active file stops at it, and every later
    /// append first retries the truncation and is refused until it
    /// succeeds, so nothing is ever appended AFTER a record that was not
    /// acknowledged (which would make it permanent).
    ///
    /// The one window this cannot close is a process that stops before a
    /// retry succeeds: the boundary lives in memory, and the realistic cause
    /// of a failed truncation (a device that went read-only) would refuse a
    /// marker file too. `tracing::error!` names the byte range so an
    /// operator can remove it.
    unacknowledged_from: Arc<AtomicU64>,
    /// The archive the append handle points into, when a rotation renamed
    /// the active file away and neither a fresh active file nor the rename
    /// back could be had.
    ///
    /// Round 29 (audit 2026-10-20, audit trail): the handle was left as it
    /// was and appends silently grew the renamed archive — a file every
    /// reader treats as immutable, whose cached statistics and persisted
    /// index then no longer described it. While this is set, appends are
    /// refused; each one first retries opening a fresh active file.
    detached_into: Arc<Mutex<Option<PathBuf>>>,
    /// Where the next record joins the hash chain (Round 30, G-07): read
    /// from the trail at open, advanced only by an append that was
    /// acknowledged — a failed write that was cut back leaves it where it
    /// was. Locked only under the append handle's lock.
    chain_head: Arc<Mutex<chain::ChainHead>>,
    /// The MAC key, when the operator configured one
    /// (`GRAPHITE_AUDIT_KEY_FILE`): what makes the trail tamper-evident
    /// rather than only corruption-evident (`chain.rs`).
    key: Option<Arc<AuditKey>>,
    /// Where a checkpoint is written at each rotation
    /// (`GRAPHITE_AUDIT_ANCHOR_DIR`), for the operator to keep on storage
    /// the writer cannot alter.
    anchor_dir: Option<Arc<PathBuf>>,
    /// Checkpoints that could not be written to `anchor_dir`.
    anchors_failed: Arc<AtomicU64>,
    /// Opened by `open_read_only`: every append is refused, and no writer
    /// lock is held, so a reader can run beside the process that writes.
    read_only: bool,
    /// The exclusive lock on `.<log>.lock` a writer holds for its lifetime
    /// (Round 30): two writers would each extend the chain from their own
    /// head and fork it, and keep disjoint indexes of one file.
    _writer_lock: Option<Arc<File>>,
    /// Test-only fault injection (`FAULT_*`): the I/O failures the paths
    /// above exist for cannot be produced on demand by a real filesystem.
    #[cfg(test)]
    faults: Arc<std::sync::atomic::AtomicU32>,
}

/// How a writable audit log is opened.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Rotate the active file past this many bytes (0 = never).
    pub rotate_bytes: u64,
    /// Archives to keep (0 = all).
    pub max_archives: usize,
    /// MAC key; `None` leaves the trail corruption-evident only.
    pub key: Option<AuditKey>,
    /// Directory a checkpoint is written to at each rotation.
    pub anchor_dir: Option<PathBuf>,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            rotate_bytes: DEFAULT_ROTATE_BYTES,
            max_archives: 0,
            key: None,
            anchor_dir: None,
        }
    }
}

impl AuditOptions {
    /// The key and anchor settings from their environment values
    /// (`GRAPHITE_AUDIT_KEY_FILE`, `GRAPHITE_AUDIT_ANCHOR_DIR`), checked
    /// against the data directory the trail lives in. Unset is `None`; set
    /// but empty, a key file that cannot be used, or an anchor directory
    /// that does not exist or lies inside the data directory is an error —
    /// an operator who meant to key or anchor the trail must not get an
    /// unkeyed or unanchored one silently.
    pub fn with_env_values(
        mut self,
        key_file: Option<&str>,
        anchor_dir: Option<&str>,
        data_dir: &Path,
    ) -> Result<Self, String> {
        if let Some(raw) = key_file {
            if raw.trim().is_empty() {
                return Err(format!("{AUDIT_KEY_ENV} is set but empty"));
            }
            self.key = Some(
                AuditKey::load(Path::new(raw.trim()), Some(data_dir))
                    .map_err(|e| format!("{AUDIT_KEY_ENV}: {e}"))?,
            );
        }
        if let Some(raw) = anchor_dir {
            if raw.trim().is_empty() {
                return Err(format!("{AUDIT_ANCHOR_ENV} is set but empty"));
            }
            let dir = PathBuf::from(raw.trim());
            let resolved = std::fs::canonicalize(&dir)
                .map_err(|e| format!("{AUDIT_ANCHOR_ENV} {}: {e}", dir.display()))?;
            if !resolved.is_dir() {
                return Err(format!(
                    "{AUDIT_ANCHOR_ENV} {} is not a directory",
                    dir.display()
                ));
            }
            if let Ok(data) = std::fs::canonicalize(data_dir) {
                if resolved.starts_with(&data) {
                    return Err(format!(
                        "{AUDIT_ANCHOR_ENV} {} is inside the data directory: a checkpoint kept beside the trail anchors nothing",
                        dir.display()
                    ));
                }
            }
            self.anchor_dir = Some(resolved);
        }
        Ok(self)
    }
}

/// `AuditLog::unacknowledged_from` when every byte of the active file was
/// acknowledged.
const NO_UNACKNOWLEDGED_BYTES: u64 = u64::MAX;

/// The faults `AuditLog::injected` can report (tests only; outside tests
/// nothing sets them).
const FAULT_SYNC: u32 = 1;
const FAULT_TRUNCATE: u32 = 2;
const FAULT_REOPEN: u32 = 4;
const FAULT_RENAME_BACK: u32 = 8;
const FAULT_ROTATE_RENAME: u32 = 16;

/// The most program ids one archive's cached statistics keep by name.
///
/// Round 29 (audit 2026-10-20, audit trail): the cache kept every distinct
/// program id of every archive, for the life of the process — memory that
/// grew with archives × distinct ids, and program ids are chosen by
/// whoever sends a request. Each archive now keeps its most frequent ids
/// (ties broken by id, so the choice is deterministic) and folds the rest
/// into `ArchiveStats::other_programs`. `observations_by_program` feeds a
/// top-five dashboard; an id outside an archive's top 256 is a tail the
/// dashboard never shows.
const MAX_PROGRAMS_PER_ARCHIVE: usize = 256;

/// The fewest bytes a verification record's line can occupy: the JSON of
/// an `AuditRecord` with every string empty is well over this. An index
/// claiming more records under one key than its archive could hold at this
/// size is not believed (`AuditLog::index_entry_is_plausible`).
const MIN_VERIFICATION_LINE: u64 = 128;

/// The first and the longest wait before an archive index that could not
/// be checked or built is tried again.
const INDEX_RETRY_FIRST: std::time::Duration = std::time::Duration::from_secs(1);
const INDEX_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);

/// How many names `next_archive_path` tries before it gives up.
/// Three in tests, so the exhausted case can be driven without creating
/// ten thousand entries.
const MAX_ARCHIVE_NAME_PROBES: u32 = if cfg!(test) { 3 } else { 9_999 };

/// Whether an archive's index can answer, as checked in this process.
#[derive(Debug, Clone)]
enum IndexState {
    Ready(ArchiveIndex),
    /// No index could be checked or built for an archive of this length.
    ///
    /// Round 29 (audit 2026-10-20, audit trail): this was final for the
    /// life of the process, so one transient failure (a full disk, an
    /// index directory briefly unwritable) condemned the archive to a full
    /// scan on every lookup until a restart. It is now retried after
    /// `retry_at`, with the wait doubling per failure up to
    /// `INDEX_RETRY_MAX`.
    Unavailable {
        len: u64,
        failures: u32,
        retry_at: std::time::Instant,
    },
}

/// A point-in-time view of audit-log health, surfaced by /health and /metrics.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct AuditHealth {
    pub writes_ok: u64,
    pub writes_failed: u64,
    /// Current size of the ACTIVE audit file in bytes (archives excluded).
    pub active_bytes: u64,
    /// Completed rotations since the process started.
    pub rotations_ok: u64,
    /// Rotations that failed and left the active file growing. Non-zero is a
    /// degraded condition: the trail is intact but unbounded.
    pub rotations_failed: u64,
    /// Rotated archives currently on disk.
    pub archive_count: u64,
    /// Whether new records carry a MAC under an operator key (Round 30,
    /// G-07). `false` is not a fault but a weaker posture: the chain is
    /// corruption-evident, and a writer to the data directory can rewrite
    /// it coherently.
    pub tamper_evident: bool,
    /// The newest record's position in the hash chain; `None` before the
    /// first chained record.
    pub chain_head_seq: Option<u64>,
    /// Rotation checkpoints that could not be written to the anchor
    /// directory. Non-zero is degraded.
    pub anchors_failed: u64,
}

/// Which verification records a read selects.
///
/// A closed set rather than a closure so that per-archive totals can be
/// cached: an archive's count of approved and blocked records never changes,
/// and the dashboard asks the same three questions on every poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSelector {
    /// Every verification record.
    All,
    /// Only records with `approved == true`.
    Approved,
    /// Only records with `approved == false` — the policy-violation feed.
    Blocked,
}

impl AuditSelector {
    fn keeps(self, r: &AuditRecord) -> bool {
        match self {
            AuditSelector::All => true,
            AuditSelector::Approved => r.approved,
            AuditSelector::Blocked => !r.approved,
        }
    }
}

/// What one scan of one audit file established. Every field is computed in
/// the same forward pass, so a file scanned for any reason yields the full
/// statistics for the cache.
#[derive(Debug, Clone, Default)]
struct ArchiveStats {
    /// File length when scanned; a mismatch on a later read invalidates the
    /// entry (an archive is never appended to, so this only ever catches a
    /// file that is not actually one of ours).
    len: u64,
    approved: usize,
    blocked: usize,
    errors: usize,
    /// Verification records per program id. Every id while a file is
    /// scanned; at most `MAX_PROGRAMS_PER_ARCHIVE` once cached.
    by_program: HashMap<String, usize>,
    /// Verification records of the ids `bounded` folded out of
    /// `by_program`.
    other_programs: usize,
}

impl ArchiveStats {
    fn records(&self, selector: AuditSelector) -> usize {
        match selector {
            AuditSelector::All => self.approved + self.blocked,
            AuditSelector::Approved => self.approved,
            AuditSelector::Blocked => self.blocked,
        }
    }

    /// The statistics as an archive's cache entry keeps them: the
    /// `MAX_PROGRAMS_PER_ARCHIVE` most frequent program ids by name, the
    /// rest folded into `other_programs`.
    fn bounded(mut self) -> ArchiveStats {
        if self.by_program.len() <= MAX_PROGRAMS_PER_ARCHIVE {
            return self;
        }
        let mut programs: Vec<(String, usize)> = self.by_program.drain().collect();
        programs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        self.other_programs += programs[MAX_PROGRAMS_PER_ARCHIVE..]
            .iter()
            .map(|(_, n)| n)
            .sum::<usize>();
        programs.truncate(MAX_PROGRAMS_PER_ARCHIVE);
        self.by_program = programs.into_iter().collect();
        self
    }
}

/// One forward pass over one file: the statistics plus the last `tail`
/// records the selector keeps and the last `tail` error records, each in
/// file order.
struct FileScan {
    stats: ArchiveStats,
    records: VecDeque<AuditRecord>,
    errors: VecDeque<AuditErrorRecord>,
}

/// Scans the first `len` bytes of `file`: the length its caller sampled, so
/// a scan never reads past the bytes it is accounting for (bytes appended
/// since, or bytes an append could not acknowledge).
fn scan_file(file: File, len: u64, tail: usize, selector: AuditSelector) -> FileScan {
    use std::io::Read;
    let mut stats = ArchiveStats {
        len,
        ..Default::default()
    };
    let mut records: VecDeque<AuditRecord> = VecDeque::new();
    let mut errors: VecDeque<AuditErrorRecord> = VecDeque::new();
    // Streamed, one line at a time: an archive can be 64 MiB.
    for_each_line(file.take(len), |line| {
        if line.trim().is_empty() {
            return;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(r) => {
                if r.approved {
                    stats.approved += 1;
                } else {
                    stats.blocked += 1;
                }
                *stats.by_program.entry(r.program_id.clone()).or_insert(0) += 1;
                if selector.keeps(&r) && tail > 0 {
                    if records.len() == tail {
                        records.pop_front();
                    }
                    records.push_back(r);
                }
            }
            Err(_) => {
                if let Ok(e) = serde_json::from_str::<AuditErrorRecord>(line) {
                    stats.errors += 1;
                    if tail > 0 {
                        if errors.len() == tail {
                            errors.pop_front();
                        }
                        errors.push_back(e);
                    }
                }
                // else: a lifecycle event, or a torn final line from a crash
                // mid-write — neither is a verification record. Skipped, never
                // an error: the log is append-only and a torn tail is expected.
            }
        }
    });
    FileScan {
        stats,
        records,
        errors,
    }
}

/// The `(stamp, seq, extra)` an archive name encodes; archives are ordered
/// by it (`AuditLog::archives`).
type ArchiveOrder = (u128, u64, u32);

/// The order encoded by `name` when it is an archive name of the log whose
/// file name is `stem`, exactly as `AuditLog::next_archive_path` builds
/// them: `<stem>.<stamp>-<seq>` with an optional `-<extra>`, where the stamp
/// is decimal milliseconds, the sequence at least six digits and the extra
/// at least four. `None` for every other name.
fn parse_archive_name(stem: &str, name: &str) -> Option<ArchiveOrder> {
    let rest = name.strip_prefix(stem)?.strip_prefix('.')?;
    let digits =
        |part: &str, min: usize| part.len() >= min && part.bytes().all(|b| b.is_ascii_digit());
    let mut parts = rest.split('-');
    let stamp = parts.next().filter(|p| digits(p, 1))?.parse().ok()?;
    let seq = parts.next().filter(|p| digits(p, 6))?.parse().ok()?;
    let extra = match parts.next() {
        None => 0,
        Some(p) if digits(p, 4) => p.parse().ok().filter(|&e: &u32| e > 0)?,
        Some(_) => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((stamp, seq, extra))
}

/// The rotated archives of the log at `path`, oldest first, each with the
/// order its name encodes. See `AuditLog::archives`.
fn archives_of(path: &Path) -> Vec<(ArchiveOrder, PathBuf)> {
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    let Some(stem) = path.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let mut archives: Vec<(ArchiveOrder, PathBuf)> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let path = e.path();
                let order = parse_archive_name(stem, path.file_name()?.to_str()?)?;
                // A directory (or anything else that is not a file) with
                // an archive's name is not one.
                path.is_file().then_some((order, path))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    archives.sort();
    archives
}

/// Walk the whole trail of the log at `path` against its hash chain:
/// every archive, oldest first, then the active file. Read-only; safe
/// beside a running writer. See `chain::verify_trail`.
pub fn verify_audit_trail(
    path: &Path,
    keys: &[AuditKey],
    checkpoint: Option<&Checkpoint>,
) -> std::io::Result<TrailReport> {
    let archives: Vec<PathBuf> = archives_of(path).into_iter().map(|(_, p)| p).collect();
    chain::verify_trail(path, &archives, keys, checkpoint)
}

/// How many times in a row an archive's index could not be had at length
/// `len`, per the state remembered for it.
fn previous_failures(state: Option<&IndexState>, len: u64) -> u32 {
    match state {
        Some(IndexState::Unavailable {
            len: at, failures, ..
        }) if *at == len => *failures,
        _ => 0,
    }
}

/// How long to wait before trying an archive's index again after its
/// `failures`-th failure in a row: `INDEX_RETRY_FIRST`, doubling, at most
/// `INDEX_RETRY_MAX`.
fn index_retry_wait(failures: u32) -> std::time::Duration {
    let doublings = failures.saturating_sub(1).min(16);
    INDEX_RETRY_FIRST
        .saturating_mul(1u32 << doublings)
        .min(INDEX_RETRY_MAX)
}

/// Make a directory entry change (a rename, a newly created file) durable.
///
/// On Unix the rename that rotation performs lives in the directory, and the
/// directory has its own write-back cache; without this a power loss after
/// rotation can leave the archive name unlinked while the data survives. On
/// Windows `MoveFileEx` is journaled by NTFS and directories cannot be
/// opened for sync, so this is a no-op there.
pub(crate) fn sync_dir(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(dir) = path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Which point in a transaction's lifecycle an audit record describes
/// (Constitution P9).
///
/// P9 requires construction, simulation, verification, signing, submission,
/// confirmation and finalization to each emit an audit event. Before this,
/// the trail carried exactly one kind of record — a verification outcome —
/// with no `event_type` at all, so six of the seven mandated events were
/// simply absent and nothing in the format could express them.
///
/// HONESTY CONSTRAINT — read before adding an emitter: Graphite is a
/// PRE-SIGNATURE verification service. It genuinely observes `Construction`,
/// `Simulation` and `Verification`, and it emits those itself. It does NOT
/// sign, submit, or watch the chain — only the caller (wallet, agent, bridge)
/// knows when those happened. Graphite therefore does not, and must not,
/// synthesize `Signing`/`Submission`/`Confirmation`/`Finalization` events on
/// its own: an audit trail that fabricates events it never witnessed is worse
/// than one that admits the gap. Those four are recorded through the
/// server's audit-event endpoint (`POST /audit/event`), by the component
/// that actually performed them, keyed to the same `content_hash` so the
/// whole lifecycle reconciles.
///
/// Where each event reaches the trail is `LifecycleEvent::emission`, one
/// `match` with no wildcard: a new event does not compile until it says
/// (R-P14, Round 28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEvent {
    /// A verified transaction plan was built from resolved accounts.
    Construction,
    /// Simulation ran (live RPC `simulateTransaction`, or the integrity check).
    Simulation,
    /// The 8-layer pipeline produced a verdict.
    Verification,
    /// The caller signed the transaction. Caller-reported.
    Signing,
    /// The caller submitted it to the network. Caller-reported.
    Submission,
    /// The network confirmed it. Caller-reported, and written by Graphite at
    /// `/verify/execution` when L8 itself saw the signature included at
    /// cluster-backed commitment (`confirmed` or `finalized`).
    Confirmation,
    /// The transaction reached finalized commitment. Caller-reported.
    Finalization,
    /// An operator changed the gate's own state: withdrawing a program from
    /// trust or restoring it (`/admin/quarantine`, `graphite quarantine`), or
    /// seeding or promoting the evidence a program's tier is computed from
    /// (`graphite evidence seed|baseline|promote-shadow`).
    ///
    /// Self-observed: Graphite performs the action itself, so a caller must not
    /// be able to report one. Otherwise anyone could write "quarantine lifted
    /// for X" into the audit trail without a quarantine ever being lifted,
    /// which is exactly the forged history `is_self_observed` exists to stop.
    /// `content_hash` carries the program id rather than a transaction hash —
    /// this event is about a program, not a transaction.
    OperatorAction,
    /// L8 checked a signature against the chain and did NOT see it included
    /// at cluster-backed commitment: unknown to the cluster, seen only at
    /// `processed`, or the RPC could not answer (audit 2026-10-20, M4).
    ///
    /// Until then every `/verify/execution` call wrote a Graphite-attested
    /// `confirmation` row whatever the chain said, so a client polling a
    /// pending transaction, or anyone holding the verify key and a made-up
    /// signature, put "Graphite observed this confirmed" on the trail. The
    /// caller's later, truthful `submission` then read as out of order. The
    /// check is still recorded, under its own name, and ranks nowhere in the
    /// lifecycle order.
    ExecutionCheck,
}

/// Where a lifecycle event reaches the audit trail (Constitution P9;
/// roadmap R-P14, Round 28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emission {
    /// Graphite observes the stage inside a verification and records it on
    /// that verification's row, not on a row of its own. `field` is the
    /// row's field that carries it.
    OnTheVerificationRow { field: &'static str },
    /// Graphite performs the stage and writes the row itself, at `route`.
    GraphiteRow { route: &'static str },
    /// The caller performs the stage and reports it at `POST /audit/event`,
    /// where it is written as an attestation. `also_observed` names the
    /// route where Graphite writes one from its own observation.
    CallerReported { also_observed: Option<&'static str> },
}

impl LifecycleEvent {
    /// Every lifecycle event. `every_lifecycle_event_reaches_the_trail`
    /// checks this list against the enum serde derives, so a variant left
    /// out of it fails the build's tests.
    pub const ALL: [LifecycleEvent; 9] = [
        LifecycleEvent::Construction,
        LifecycleEvent::Simulation,
        LifecycleEvent::Verification,
        LifecycleEvent::Signing,
        LifecycleEvent::Submission,
        LifecycleEvent::Confirmation,
        LifecycleEvent::Finalization,
        LifecycleEvent::OperatorAction,
        LifecycleEvent::ExecutionCheck,
    ];

    /// Where this event reaches the trail.
    ///
    /// No wildcard arm, on purpose: a new lifecycle stage does not compile
    /// until it is given an emitter here, and
    /// `server::tests::every_lifecycle_event_reaches_the_trail` drives every
    /// emitter this names and reads the row back.
    ///
    /// Construction and simulation have no row of their own. A verification
    /// is the only path that constructs or simulates, and its row records
    /// both: the instruction plan it judged (`content_hash`) and the
    /// simulation layer's state (`l3_status`). A separate row for each would
    /// be two more device syncs per verdict carrying nothing the
    /// verification row does not.
    pub const fn emission(self) -> Emission {
        match self {
            LifecycleEvent::Construction => Emission::OnTheVerificationRow {
                field: "content_hash",
            },
            LifecycleEvent::Simulation => Emission::OnTheVerificationRow { field: "l3_status" },
            LifecycleEvent::Verification => Emission::GraphiteRow { route: "/verify" },
            LifecycleEvent::Signing => Emission::CallerReported {
                also_observed: None,
            },
            LifecycleEvent::Submission => Emission::CallerReported {
                also_observed: None,
            },
            LifecycleEvent::Confirmation => Emission::CallerReported {
                also_observed: Some("/verify/execution"),
            },
            LifecycleEvent::Finalization => Emission::CallerReported {
                also_observed: None,
            },
            LifecycleEvent::OperatorAction => Emission::GraphiteRow {
                route: "/admin/quarantine",
            },
            LifecycleEvent::ExecutionCheck => Emission::GraphiteRow {
                route: "/verify/execution",
            },
        }
    }

    /// True for the events Graphite itself witnesses and emits.
    ///
    /// The complement is caller-reported: Graphite has no way to observe it
    /// and must not invent it. Read from `emission`, so the two cannot
    /// disagree.
    pub fn is_self_observed(&self) -> bool {
        !matches!(self.emission(), Emission::CallerReported { .. })
    }
}

/// Default for records written before `event_type` existed: every one of them
/// was a verification outcome, so deserializing an old log yields the correct
/// classification rather than failing or guessing.
fn default_event_type() -> LifecycleEvent {
    LifecycleEvent::Verification
}

/// A minimal, self-contained record of a verification outcome. Deliberately
/// excludes the raw account list / instruction payload — the deterministic
/// `content_hash` and `audit_trail_id` are the linkage keys for any deeper
/// forensic lookup (Constitution P4/P5: enough to reproduce, not to leak).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    /// Which lifecycle stage this record describes (P9). `#[serde(default)]`
    /// keeps existing append-only logs readable: records written before this
    /// field existed were all verifications.
    #[serde(default = "default_event_type")]
    pub event_type: LifecycleEvent,
    pub timestamp: String,
    pub audit_trail_id: String,
    pub content_hash: String,
    /// `scope.transaction_sha256` when the verification was artifact-bound:
    /// the exact transaction this verdict is about. `None` for a descriptive
    /// verdict and for rows written before Round 10. This — not
    /// `content_hash`, which is one instruction's projection and is shared
    /// by every transaction carrying that instruction — is what an
    /// execution is joined to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_sha256: Option<String>,
    pub program_id: String,
    pub instruction_name: String,
    pub protocol_name: String,
    pub manifest_version: Option<String>,
    pub approved: bool,
    /// The verdict's `decision` (Round 30, G-01): `executable_approved`,
    /// `analysis_only`, `inconclusive` or `blocked`. `approved` alone never
    /// said whether the transaction could be signed. `None` on rows written
    /// before Round 30 and on rows that are not verifications — "not
    /// reported", never read as either answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// The verdict's `executable` (Round 30). `None` as `decision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    pub confidence: f64,
    pub risk_status: String,
    pub policy_verdict: String,
    /// L3 simulation verdict as emitted by the layer (passed/failed/inconclusive)
    /// — GAP-2026-08-06-3: the audit trail must reflect the REAL layer states.
    pub l3_status: String,
    /// L8 execution-verification state (always "inconclusive" until Phase 2
    /// wires post-submission verification) — GAP-2026-08-06-3.
    pub l8_status: String,
    /// The wallet profile the verdict was judged under, and — when the server
    /// overrode what the caller asked for — the override (A4-06, 2026-09-29
    /// audit). A verdict's meaning depends on its thresholds; the override
    /// was disclosed in the response only, so the trail could not say which
    /// policy an approval was held to. `None` on rows written before, and on
    /// rows not produced by `/verify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_profile: Option<String>,
}

/// How a verification record is looked up, most exact first.
///
/// `content_hash` is one instruction's projection — program, discriminator,
/// accounts, data, CPI targets — and every transaction carrying that
/// instruction shares it: the same transfer with a different sibling, fee
/// payer, signer set or blockhash is a different transaction with the same
/// `content_hash`. Until Round 10 it was the only join key, so L8 and
/// `verdict_on_record` could answer for the wrong transaction — the approval
/// of A returned for the execution of B. `transaction_sha256` names the exact
/// bytes; `audit_trail_id` names the exact verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKey<'a> {
    /// The unique id of one verification (`gr-<uuid>`).
    AuditTrailId(&'a str),
    /// The digest of the exact artifact — every verification of those bytes.
    TransactionSha256(&'a str),
    /// The instruction-level identifier — every transaction carrying that
    /// instruction. Ambiguous by construction; the coarsest key.
    ContentHash(&'a str),
}

/// The key a lookup resolved by, recorded on the row that used it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationKeyKind {
    AuditTrailId,
    TransactionSha256,
    ContentHash,
}

impl VerificationKey<'_> {
    pub fn kind(&self) -> VerificationKeyKind {
        match self {
            VerificationKey::AuditTrailId(_) => VerificationKeyKind::AuditTrailId,
            VerificationKey::TransactionSha256(_) => VerificationKeyKind::TransactionSha256,
            VerificationKey::ContentHash(_) => VerificationKeyKind::ContentHash,
        }
    }
    fn value(&self) -> &str {
        match self {
            VerificationKey::AuditTrailId(v)
            | VerificationKey::TransactionSha256(v)
            | VerificationKey::ContentHash(v) => v,
        }
    }
    /// The index entry for this key.
    fn index_key(&self) -> String {
        match self {
            VerificationKey::AuditTrailId(v) => format!("id:{v}"),
            VerificationKey::TransactionSha256(v) => format!("tx:{v}"),
            VerificationKey::ContentHash(v) => format!("ch:{v}"),
        }
    }
    fn matches(&self, r: &AuditRecord) -> bool {
        match self {
            VerificationKey::AuditTrailId(v) => r.audit_trail_id == *v,
            VerificationKey::TransactionSha256(v) => r.transaction_sha256.as_deref() == Some(*v),
            VerificationKey::ContentHash(v) => r.content_hash == *v,
        }
    }
}

/// Every index entry one verification record contributes.
fn index_keys(r: &AuditRecord) -> Vec<String> {
    let mut keys = vec![
        VerificationKey::AuditTrailId(&r.audit_trail_id).index_key(),
        VerificationKey::ContentHash(&r.content_hash).index_key(),
    ];
    if let Some(tx) = &r.transaction_sha256 {
        keys.push(VerificationKey::TransactionSha256(tx).index_key());
    }
    keys
}

/// What the trail held for a lifecycle event's `content_hash` at the moment
/// the event was recorded — computed by Graphite, never reported by the
/// caller.
///
/// A caller-reported event is an attestation about the caller's own action.
/// This field is the one fact about it Graphite can establish itself: whether
/// the verification the event claims to follow exists, and what it decided.
/// A `signing` reported against a verdict Graphite BLOCKED is the gate being
/// bypassed, visible at signing time instead of after L8; a report against
/// a hash with no verification on record is an event about nothing Graphite
/// examined. Neither is refused — the trail records what was reported — but
/// both are named on the row, counted, and logged loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOnRecord {
    /// The most recent verification of this hash was an approval.
    Approved,
    /// The most recent verification of this hash was a block.
    Blocked,
    /// No verification of this hash exists anywhere in the trail.
    NotFound,
}

/// A lifecycle event for a stage Graphite does not itself perform — and the
/// lifecycle rows Graphite writes from its own observation (the L8
/// reconciliation, an operator action), which carry `observed_by_graphite`
/// or a self-observed `event_type`.
///
/// Deliberately separate from `AuditRecord`: that type carries a verification
/// VERDICT (confidence, risk status, layer states), and none of those fields
/// are meaningful for "the caller signed this" — filling them with defaults
/// would put fabricated verdict data in the audit trail. This record carries
/// only what is actually known at that stage.
///
/// `content_hash` is the join key back to the verification that approved this
/// exact transaction, so a reviewer can reconstruct the full lifecycle. It is
/// caller-supplied and therefore caller-attested, not proof: the record states
/// what the caller reported, and `reported_by` names who reported it. Graphite
/// does not and cannot independently confirm a signing or submission it did
/// not perform — recording it as attestation is honest, recording it as fact
/// would not be.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LifecycleEventRecord {
    pub event_type: LifecycleEvent,
    pub timestamp: String,
    /// Links this event to the verification that approved the transaction.
    pub content_hash: String,
    /// What the trail said about `content_hash` when this row was written.
    /// `None` on rows written before the field existed and on rows whose
    /// writer did not consult the trail (the L8 reconciliation row carries
    /// its answer in `detail` instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_on_record: Option<VerdictOnRecord>,
    /// Which key `verdict_on_record` was resolved by. `content_hash` means
    /// the answer is about *a* transaction carrying that instruction, not
    /// necessarily this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_on_record_key: Option<VerificationKeyKind>,
    /// The exact transaction the caller says this event is about, when it
    /// supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_sha256: Option<String>,
    /// The verification's audit trail id, when the caller has it.
    #[serde(default)]
    pub audit_trail_id: Option<String>,
    /// On-chain signature, once one exists (submission onward).
    #[serde(default)]
    pub transaction_signature: Option<String>,
    /// Who reported the event — an operator-meaningful identifier for the
    /// wallet/agent/bridge, never a credential.
    #[serde(default)]
    pub reported_by: Option<String>,
    /// Free-form detail (e.g. a confirmation slot, or a failure reason).
    #[serde(default)]
    pub detail: Option<String>,
    /// True on rows Graphite wrote from its own observation — today the L8
    /// reconciliation row — as opposed to a caller's attestation (Round 12).
    /// Rows written before the field existed were all caller-reported.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub observed_by_graphite: bool,
    /// How this row sits against the rows already on record for the same
    /// transaction, computed by Graphite when it was written (Round 12): a
    /// duplicate of an earlier report, an event out of the signing →
    /// submission → confirmation → finalization order, an event whose
    /// predecessor was never reported, or a signature that differs from
    /// the one already attached to this transaction. Recorded, never
    /// refused — the trail keeps what was reported — and empty when the
    /// row is in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sequence_anomalies: Vec<String>,
}

/// How long after a rotation `lifecycle_history` keeps merging the newest
/// archive with the active file (Round 17, F-15-09). A lifecycle — signing,
/// submission, confirmation, reconciliation — spans seconds to a few
/// minutes; ten covers a slow confirmation and a retried L8.
pub const ROTATION_STRADDLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// The most lifecycle rows kept per key in the index and consulted for a
/// sequence check. A transaction has a handful; a caller reporting hundreds
/// for one key is itself the anomaly, and the memory it could otherwise
/// size is bounded here.
pub const MAX_LIFECYCLE_HISTORY: usize = 64;

/// The keys by which a transaction's lifecycle rows are gathered: any one
/// of them matching a row is a match, because a caller does not always hold
/// all three.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LifecycleKey<'a> {
    pub audit_trail_id: Option<&'a str>,
    pub transaction_sha256: Option<&'a str>,
    pub transaction_signature: Option<&'a str>,
}

impl LifecycleKey<'_> {
    fn index_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        if let Some(id) = self.audit_trail_id.map(str::trim).filter(|v| !v.is_empty()) {
            keys.push(format!("lc:id:{id}"));
        }
        if let Some(tx) = self
            .transaction_sha256
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            keys.push(format!("lc:tx:{tx}"));
        }
        if let Some(sig) = self
            .transaction_signature
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            keys.push(format!("lc:sig:{sig}"));
        }
        keys
    }
    fn is_empty(&self) -> bool {
        self.index_keys().is_empty()
    }
    fn matches(&self, r: &LifecycleEventRecord) -> bool {
        let same = |a: Option<&str>, b: Option<&str>| match (a, b) {
            (Some(a), Some(b)) => !a.trim().is_empty() && a.trim() == b.trim(),
            _ => false,
        };
        same(self.audit_trail_id, r.audit_trail_id.as_deref())
            || same(self.transaction_sha256, r.transaction_sha256.as_deref())
            || same(
                self.transaction_signature,
                r.transaction_signature.as_deref(),
            )
    }
}

impl LifecycleEventRecord {
    /// The keys this row is indexed under.
    fn lifecycle_keys(&self) -> Vec<String> {
        LifecycleKey {
            audit_trail_id: self.audit_trail_id.as_deref(),
            transaction_sha256: self.transaction_sha256.as_deref(),
            transaction_signature: self.transaction_signature.as_deref(),
        }
        .index_keys()
    }
}

/// An audit record for a verification that FAILED before producing a result
/// (400 bad-input, 500 internal error). Rejected-by-error requests — probing
/// attacks, malformed payloads, oversized bodies — leave a trail instead of
/// silently vanishing from the audit log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditErrorRecord {
    pub timestamp: String,
    pub program_id: String,
    pub instruction_name: String,
    pub error: String,
    pub error_type: String,
    pub status: u16,
}

/// The longest any single field of an error record may be on disk.
///
/// Generous for a genuine diagnostic and small enough that no request can turn
/// the audit trail into storage the caller controls.
pub const MAX_AUDIT_FIELD_CHARS: usize = 256;

/// The longest a lifecycle event's free-form `detail` may be, at the
/// boundary (`/audit/event`) and on disk alike. One constant on purpose:
/// until Round 11 the boundary accepted 1024 characters and the disk kept
/// 256, so the server's own L8 detail — the reconciliation, the attribution,
/// a rejected-bytes reason — was cut off before the part an investigator
/// needs.
pub const MAX_LIFECYCLE_DETAIL_CHARS: usize = 1024;

fn bound_detail(value: &str) -> String {
    if value.chars().count() <= MAX_LIFECYCLE_DETAIL_CHARS {
        return value.to_string();
    }
    let kept: String = value.chars().take(MAX_LIFECYCLE_DETAIL_CHARS).collect();
    format!("{kept}… [truncated, {} chars total]", value.chars().count())
}

fn bound_field(value: &str) -> String {
    if value.chars().count() <= MAX_AUDIT_FIELD_CHARS {
        return value.to_string();
    }
    let kept: String = value.chars().take(MAX_AUDIT_FIELD_CHARS).collect();
    // Record what was dropped: a silently shortened field would make an
    // investigator believe they were reading the whole value.
    format!("{kept}… [truncated, {} chars total]", value.chars().count())
}

impl LifecycleEventRecord {
    /// Every caller-supplied field bounded to `MAX_AUDIT_FIELD_CHARS`
    /// (`detail` to `MAX_LIFECYCLE_DETAIL_CHARS`), with truncation recorded.
    /// Defence in depth behind the length checks in
    /// `lifecycle_event_handler`; see `AuditErrorRecord::bounded`.
    fn bounded(&self) -> LifecycleEventRecord {
        LifecycleEventRecord {
            event_type: self.event_type,
            timestamp: self.timestamp.clone(),
            content_hash: bound_field(&self.content_hash),
            verdict_on_record: self.verdict_on_record,
            verdict_on_record_key: self.verdict_on_record_key,
            transaction_sha256: self.transaction_sha256.as_deref().map(bound_field),
            audit_trail_id: self.audit_trail_id.as_deref().map(bound_field),
            transaction_signature: self.transaction_signature.as_deref().map(bound_field),
            reported_by: self.reported_by.as_deref().map(bound_field),
            detail: self.detail.as_deref().map(bound_detail),
            observed_by_graphite: self.observed_by_graphite,
            sequence_anomalies: self
                .sequence_anomalies
                .iter()
                .take(8)
                .map(|a| bound_detail(a))
                .collect(),
        }
    }
}

impl AuditErrorRecord {
    /// The record as it may be written to disk, with every caller-influenced
    /// field bounded.
    ///
    /// Defence in depth behind the entry-point length caps in `verify_async`.
    /// Those stop the known path — an oversized `program_id` reaching this
    /// record — but the audit trail is a P9 guarantee and it must not be
    /// possible for ANY future code path to let a caller choose how many bytes
    /// land on the operator's volume. Found 2026-09-06: a 100,000-character
    /// `program_id` was written here verbatim, so probing alone grew
    /// `/data/audit.jsonl` to 3.6 MB. Burying real verifications under chosen
    /// padding degrades the trail as effectively as deleting it, and disk
    /// exhaustion sits behind that.
    fn bounded(&self) -> AuditErrorRecord {
        AuditErrorRecord {
            timestamp: self.timestamp.clone(),
            program_id: bound_field(&self.program_id),
            instruction_name: bound_field(&self.instruction_name),
            error: bound_field(&self.error),
            error_type: bound_field(&self.error_type),
            status: self.status,
        }
    }
}

/// A lifecycle row, as distinguished from a verification row sharing the
/// same file: it deserializes as one AND its event is not the verification
/// stage (a verification record also carries `event_type`, `timestamp` and
/// `content_hash`, so it would otherwise read as a lifecycle row with every
/// other field defaulted).
fn lifecycle_row(line: &[u8]) -> Option<LifecycleEventRecord> {
    serde_json::from_slice::<LifecycleEventRecord>(line)
        .ok()
        .filter(|r| r.event_type != LifecycleEvent::Verification)
}

/// Keep a key's FIRST and its most RECENT rows (Round 19, F-19-20).
///
/// This kept the first `MAX_LIFECYCLE_HISTORY` offsets and dropped the rest,
/// so a key holder could pre-fill a transaction's history with 64 rows and
/// every later genuine report — a conflicting signature, an out-of-order
/// confirmation — was compared against a history that did not contain it.
/// Keeping only the most recent would let the same spam push out the
/// earliest rows (the signing record a later report must agree with). Half
/// the budget holds the first rows permanently; the other half rolls.
fn push_lifecycle_offset(index: &mut HashMap<String, Vec<u64>>, key: String, offset: u64) {
    let entry = index.entry(key).or_default();
    if entry.len() >= MAX_LIFECYCLE_HISTORY {
        entry.remove(MAX_LIFECYCLE_HISTORY / 2);
    }
    entry.push(offset);
}

/// Verification records per index key in the active file, by verdict, and
/// the number of the file's bytes they account for.
///
/// `len` is what makes the counts safe to answer from. Every append adds
/// exactly the bytes it wrote, and only when the whole write succeeded;
/// rotation resets it to the fresh file's zero. A write that failed part-way,
/// or anything else that changed the file, leaves `len` short of the file's
/// real length, and a count looked up then is recounted from the file
/// instead (`AuditLog::count_verifications`).
#[derive(Debug, Default)]
struct ActiveCounts {
    /// Index key (as `index_keys`) → (approved, refused).
    by_key: HashMap<String, (usize, usize)>,
    len: u64,
}

impl ActiveCounts {
    fn record(&mut self, keys: &[String], approved: bool) {
        for k in keys {
            let entry = self.by_key.entry(k.clone()).or_insert((0, 0));
            if approved {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
    }
}

/// The three indexes of the active file.
type ActiveIndexes = (
    HashMap<String, u64>,
    HashMap<String, Vec<u64>>,
    ActiveCounts,
);

/// One pass over the active file: the offset of the last verification line
/// per key, the offsets of every lifecycle row per transaction key, and the
/// verification records per key by verdict. A torn final line and an error
/// record are neither and are skipped.
fn build_indexes(path: &Path) -> ActiveIndexes {
    build_indexes_upto(path, u64::MAX)
}

/// `build_indexes` over the first `limit` bytes of the file only: the
/// active file while bytes past `limit` were never acknowledged
/// (`AuditLog::unacknowledged_from`).
fn build_indexes_upto(path: &Path, limit: u64) -> ActiveIndexes {
    use std::io::Read;
    let mut index = HashMap::new();
    let mut lifecycle = HashMap::new();
    let mut counts = ActiveCounts::default();
    let Ok(file) = File::open(path) else {
        return (index, lifecycle, counts);
    };
    let mut reader = BufReader::new(file.take(limit));
    let mut offset: u64 = 0;
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        // Bytes, not `read_line`: a single line of invalid UTF-8 (a torn
        // write, a disk fault) would otherwise end the scan and leave every
        // later record unindexed — and an unindexed hash reads as "no
        // verification on record". One bad line skips one line.
        let Ok(n) = reader.read_until(b'\n', &mut line) else {
            break;
        };
        if n == 0 {
            break;
        }
        if let Ok(r) = serde_json::from_slice::<AuditRecord>(&line) {
            let keys = index_keys(&r);
            counts.record(&keys, r.approved);
            for k in keys {
                index.insert(k, offset);
            }
        } else if let Some(r) = lifecycle_row(&line) {
            for k in r.lifecycle_keys() {
                push_lifecycle_offset(&mut lifecycle, k, offset);
            }
        }
        offset += n as u64;
    }
    counts.len = offset;
    (index, lifecycle, counts)
}

impl AuditLog {
    /// Open (creating if needed) the audit log at `path`. The parent
    /// directory must already exist (callers create the data dir first).
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::open_with_rotation(path, DEFAULT_ROTATE_BYTES, 0)
    }

    /// Open with explicit rotation settings. `rotate_bytes == 0` disables
    /// rotation entirely; `max_archives == 0` keeps every archive (default).
    ///
    /// With rotation disabled the active file is never bounded, and neither
    /// are the in-memory indexes of it (`active_index`, `lifecycle_index`,
    /// `active_counts`): they hold an entry per distinct key the file has
    /// ever recorded, so memory grows with the trail for the life of the
    /// process. Rotation is what bounds them.
    pub fn open_with_rotation(
        path: impl AsRef<Path>,
        rotate_bytes: u64,
        max_archives: usize,
    ) -> std::io::Result<Self> {
        Self::open_with_options(
            path,
            AuditOptions {
                rotate_bytes,
                max_archives,
                ..AuditOptions::default()
            },
        )
    }

    /// Open for writing with every option, taking the writer lock on
    /// `.<log>.lock` (Round 30): a second writer — another server, or a CLI
    /// command beside a running one — is refused with `WouldBlock` instead
    /// of forking the hash chain.
    ///
    /// The chain resumes after the newest chained record on disk, which
    /// must match its own hash (and its MAC, when it is under `key`). A
    /// trail whose newest record is MAC'd cannot be continued without a
    /// key: that would downgrade it silently.
    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: AuditOptions,
    ) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = Self::take_writer_lock(&path)?;
        let existed = path.exists();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let head = Self::resume_chain(&path, options.key.as_ref())?;
        if !existed {
            // Round 29 (audit 2026-10-20, audit trail): the directory entry
            // of a newly created log was never synced, so a power loss soon
            // after the first start could lose the file's NAME — and every
            // record synced into it — even though each append was synced.
            // Rotation already synced the directory for the files it creates.
            sync_dir(&path);
        }
        let (active_index, lifecycle_index, active_counts) = build_indexes(&path);
        let torn = ends_without_newline(&path);
        if torn {
            tracing::warn!(
                "audit log {} ends in a partial line (an interrupted write); the next record starts on a new line",
                path.display()
            );
        }
        Ok(Self {
            torn_tail: Arc::new(std::sync::atomic::AtomicBool::new(torn)),
            file: std::sync::Arc::new(Mutex::new(file)),
            path: Arc::new(path),
            rotate_bytes: options.rotate_bytes,
            max_archives: options.max_archives,
            chain_head: Arc::new(Mutex::new(head)),
            key: options.key.map(Arc::new),
            anchor_dir: options.anchor_dir.map(Arc::new),
            anchors_failed: Arc::new(AtomicU64::new(0)),
            read_only: false,
            _writer_lock: Some(Arc::new(lock)),
            writes_ok: Arc::new(AtomicU64::new(0)),
            writes_failed: Arc::new(AtomicU64::new(0)),
            rotation_seq: Arc::new(AtomicU64::new(0)),
            last_stamp: Arc::new(Mutex::new(None)),
            rotations_ok: Arc::new(AtomicU64::new(0)),
            rotations_failed: Arc::new(AtomicU64::new(0)),
            archive_stats: Arc::new(Mutex::new(HashMap::new())),
            archive_indexes: Arc::new(Mutex::new(HashMap::new())),
            index_build: Arc::new(Mutex::new(())),
            archive_index_builds: Arc::new(AtomicU64::new(0)),
            archive_scans: Arc::new(AtomicU64::new(0)),
            index_jobs: Arc::new(AtomicU64::new(0)),
            active_index: Arc::new(Mutex::new(active_index)),
            lifecycle_index: Arc::new(Mutex::new(lifecycle_index)),
            active_counts: Arc::new(Mutex::new(active_counts)),
            active_count_scans: Arc::new(AtomicU64::new(0)),
            active_lookup_scans: Arc::new(AtomicU64::new(0)),
            // A freshly opened log may sit beside an archive written by the
            // process that just exited; treat open as a rotation so that
            // archive is consulted for the first window.
            last_rotation: Arc::new(Mutex::new(Some(std::time::Instant::now()))),
            unacknowledged_from: Arc::new(AtomicU64::new(NO_UNACKNOWLEDGED_BYTES)),
            detached_into: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            faults: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }

    /// Open an existing trail to READ it: no writer lock, no file created,
    /// and every append refused. For a process that only reads — `graphite
    /// execution` beside a running server — so it never competes with the
    /// writer for the lock or extends the chain from a head of its own.
    pub fn open_read_only(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let (active_index, lifecycle_index, active_counts) = build_indexes(&path);
        let torn = ends_without_newline(&path);
        Ok(Self {
            torn_tail: Arc::new(std::sync::atomic::AtomicBool::new(torn)),
            file: std::sync::Arc::new(Mutex::new(file)),
            path: Arc::new(path),
            rotate_bytes: 0,
            max_archives: 0,
            chain_head: Arc::new(Mutex::new(chain::ChainHead::genesis())),
            key: None,
            anchor_dir: None,
            anchors_failed: Arc::new(AtomicU64::new(0)),
            read_only: true,
            _writer_lock: None,
            writes_ok: Arc::new(AtomicU64::new(0)),
            writes_failed: Arc::new(AtomicU64::new(0)),
            rotation_seq: Arc::new(AtomicU64::new(0)),
            last_stamp: Arc::new(Mutex::new(None)),
            rotations_ok: Arc::new(AtomicU64::new(0)),
            rotations_failed: Arc::new(AtomicU64::new(0)),
            archive_stats: Arc::new(Mutex::new(HashMap::new())),
            archive_indexes: Arc::new(Mutex::new(HashMap::new())),
            index_build: Arc::new(Mutex::new(())),
            archive_index_builds: Arc::new(AtomicU64::new(0)),
            archive_scans: Arc::new(AtomicU64::new(0)),
            index_jobs: Arc::new(AtomicU64::new(0)),
            active_index: Arc::new(Mutex::new(active_index)),
            lifecycle_index: Arc::new(Mutex::new(lifecycle_index)),
            active_counts: Arc::new(Mutex::new(active_counts)),
            active_count_scans: Arc::new(AtomicU64::new(0)),
            active_lookup_scans: Arc::new(AtomicU64::new(0)),
            last_rotation: Arc::new(Mutex::new(Some(std::time::Instant::now()))),
            unacknowledged_from: Arc::new(AtomicU64::new(NO_UNACKNOWLEDGED_BYTES)),
            detached_into: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            faults: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }

    /// The writer lock of the log at `path`: an exclusive advisory lock on
    /// `.<log>.lock`, released by the OS on any exit. Dot-prefixed so it
    /// never shares the `<log>.` prefix of the trail's archives.
    fn take_writer_lock(path: &Path) -> std::io::Result<File> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let lock_path = path.with_file_name(format!(".{name}.lock"));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        match lock.try_lock() {
            Ok(()) => Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "the audit trail {} is held by another writer ({} is locked). Two writers would fork its hash chain: stop the other process, or use the running server's endpoints",
                    path.display(),
                    lock_path.display()
                ),
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// Where the chain resumes for the trail at `path` (`chain::resume_head`).
    fn resume_chain(path: &Path, key: Option<&AuditKey>) -> std::io::Result<chain::ChainHead> {
        let mut archives: Vec<PathBuf> = archives_of(path).into_iter().map(|(_, p)| p).collect();
        archives.reverse();
        chain::resume_head(path, &archives, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Whether a test injected the fault `_bit`; always false outside tests.
    fn injected(&self, _bit: u32) -> bool {
        #[cfg(test)]
        {
            self.faults.load(Ordering::SeqCst) & _bit != 0
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// How many bytes of an active file of length `actual` a reader may
    /// read: all of them, unless an append could not remove bytes it did
    /// not acknowledge (`unacknowledged_from`).
    fn acknowledged_len(&self, actual: u64) -> u64 {
        actual.min(self.unacknowledged_from.load(Ordering::SeqCst))
    }

    /// Whether the append handle points into a renamed archive
    /// (`detached_into`).
    fn is_detached(&self) -> bool {
        match self.detached_into.lock() {
            Ok(g) => g.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
    }

    /// Current audit-log health for /health and /metrics.
    pub fn health(&self) -> AuditHealth {
        AuditHealth {
            writes_ok: self.writes_ok.load(Ordering::Relaxed),
            writes_failed: self.writes_failed.load(Ordering::Relaxed),
            active_bytes: std::fs::metadata(self.path.as_ref())
                .map(|m| m.len())
                .unwrap_or(0),
            rotations_ok: self.rotations_ok.load(Ordering::Relaxed),
            rotations_failed: self.rotations_failed.load(Ordering::Relaxed),
            archive_count: self.archives().len() as u64,
            tamper_evident: self.key.is_some(),
            chain_head_seq: {
                let head = self.chain_head_now();
                head.next_seq.checked_sub(1)
            },
            anchors_failed: self.anchors_failed.load(Ordering::Relaxed),
        }
    }

    /// The chain head, as of now.
    fn chain_head_now(&self) -> chain::ChainHead {
        match self.chain_head.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// The id of the key new records are MAC'd under, when there is one.
    pub fn key_id(&self) -> Option<&str> {
        self.key.as_deref().map(AuditKey::id)
    }

    /// Walk the whole trail — every archive, then the active file — and
    /// check every record against the hash chain, the MACs whose keys are in
    /// `keys` (the configured key is always among them), and `checkpoint`.
    /// Never consults an index.
    pub fn verify(
        &self,
        keys: &[AuditKey],
        checkpoint: Option<&Checkpoint>,
    ) -> std::io::Result<TrailReport> {
        let mut all: Vec<AuditKey> = keys.to_vec();
        if let Some(k) = &self.key {
            all.push((**k).clone());
        }
        verify_audit_trail(self.path.as_ref(), &all, checkpoint)
    }

    /// A checkpoint of the chain's head as this writer holds it: for an
    /// operator to anchor outside the data directory. `None` before the
    /// first chained record.
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        let _guard = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let head = self.chain_head_now();
        let seq = head.next_seq.checked_sub(1)?;
        Some(Checkpoint::new(
            &self.log_name(),
            seq,
            &hex::encode(head.prev),
            seq.saturating_add(1),
            self.key.as_deref(),
        ))
    }

    fn log_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Write a checkpoint of the head to the anchor directory, when one is
    /// configured. Called under the append lock, after a rotation.
    fn write_anchor(&self) {
        let Some(dir) = &self.anchor_dir else {
            return;
        };
        let head = self.chain_head_now();
        let Some(seq) = head.next_seq.checked_sub(1) else {
            return;
        };
        let cp = Checkpoint::new(
            &self.log_name(),
            seq,
            &hex::encode(head.prev),
            seq.saturating_add(1),
            self.key.as_deref(),
        );
        let path = dir.join(format!("{}-checkpoint-{seq:020}.json", self.log_name()));
        let written = serde_json::to_vec_pretty(&cp)
            .map_err(std::io::Error::other)
            .and_then(|bytes| {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                f.write_all(&bytes)?;
                f.write_all(b"\n")?;
                f.sync_all()
            });
        match written {
            Ok(()) => {
                sync_dir(&path);
                tracing::info!("audit checkpoint seq {seq} written to {}", path.display());
            }
            Err(e) => {
                self.anchors_failed.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    "audit checkpoint seq {seq} could not be written to {}: {e}",
                    path.display()
                );
            }
        }
    }

    /// Every rotated archive on disk, oldest first.
    ///
    /// Only names `next_archive_path` generates are archives:
    /// `<log>.<stamp>-<seq>` and `<log>.<stamp>-<seq>-<extra>`, every part
    /// decimal digits. Round 29 (audit 2026-10-20, audit trail): any
    /// `<log>.*` used to count, so an operator's `audit.jsonl.bak` was read
    /// as an archive — its records counted twice, sorted as the NEWEST
    /// archive (a letter sorts after a digit), and counted against
    /// `max_archives`, so pruning deleted a real archive to make room for
    /// it.
    ///
    /// Ordered by the parsed `(stamp, seq, extra)`, not by the name's text:
    /// lexical order held only while every stamp and sequence had the same
    /// number of digits.
    fn archives(&self) -> Vec<PathBuf> {
        self.archives_ordered()
            .into_iter()
            .map(|(_, path)| path)
            .collect()
    }

    /// `archives`, each with the order its name encodes.
    fn archives_ordered(&self) -> Vec<(ArchiveOrder, PathBuf)> {
        archives_of(self.path.as_ref())
    }

    /// The trail as it is at one instant: the archive list and an open handle
    /// on the active file, taken under the append lock.
    ///
    /// Rotation happens under that lock, so it cannot slip between the two
    /// steps. Without the lock a rotation in the gap would either hide the
    /// just-rotated archive from this read (listed before the rename, opened
    /// after) or count it twice (opened before, listed after). The lock is
    /// held for a `read_dir` and an `open` — no scanning happens under it.
    fn snapshot(&self) -> (Vec<PathBuf>, Option<(File, u64)>) {
        let _guard = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let archives = self.archives();
        // While the append handle writes into an archive, whatever sits at
        // the active path is not the trail's active file.
        if self.is_detached() {
            return (archives, None);
        }
        let active = File::open(self.path.as_ref()).ok().and_then(|f| {
            f.metadata()
                .ok()
                .map(|m| (f, self.acknowledged_len(m.len())))
        });
        (archives, active)
    }

    /// Statistics for one archive, from the cache or from one scan.
    ///
    /// Returns the scan too when one had to happen, so a caller that also
    /// needs the file's records does not read it twice.
    fn archive_scan(
        &self,
        path: &Path,
        tail: usize,
        selector: AuditSelector,
        need_records: impl FnOnce(&ArchiveStats) -> bool,
    ) -> Option<(ArchiveStats, Option<FileScan>)> {
        let len = std::fs::metadata(path).ok()?.len();
        if let Some(stats) = self.cached_stats(path, len) {
            // Only the cached statistics know whether this archive can
            // contribute anything the caller still lacks. Deciding without
            // them — for example "the error tail is not full yet" — made the
            // read path rescan every archive on every poll in the common
            // case of a trail with no error records at all, which is the
            // cost the cache exists to remove (caught by
            // `archive_statistics_are_cached_and_track_pruning`).
            if !need_records(&stats) {
                return Some((stats, None));
            }
        }
        let file = File::open(path).ok()?;
        let mut scan = scan_file(file, len, tail, selector);
        // Bounded before it is cached AND before it is returned, so the
        // first read of an archive answers as every later one will.
        scan.stats = std::mem::take(&mut scan.stats).bounded();
        if let Ok(mut cache) = self.archive_stats.lock() {
            cache.insert(path.to_path_buf(), scan.stats.clone());
        }
        Some((scan.stats.clone(), Some(scan)))
    }

    /// The cached statistics for an archive, if present and still valid
    /// for its current length.
    fn cached_stats(&self, path: &Path, len: u64) -> Option<ArchiveStats> {
        let cache = self.archive_stats.lock().ok()?;
        cache.get(path).filter(|s| s.len == len).cloned()
    }

    /// Drop cache entries for archives that no longer exist (pruned).
    fn forget_missing_archives(&self, present: &[PathBuf]) {
        if let Ok(mut cache) = self.archive_stats.lock() {
            cache.retain(|p, _| present.contains(p));
        }
        if let Ok(mut indexes) = self.archive_indexes.lock() {
            indexes.retain(|p, _| present.contains(p));
        }
    }

    /// Where the archives' indexes are kept: `<log>-index/` beside the log.
    /// Not `<log>.…`, which `archives()` would list as an archive.
    fn index_dir(&self) -> Option<PathBuf> {
        let dir = self.path.parent()?;
        let stem = self.path.file_name()?.to_str()?;
        Some(dir.join(format!("{stem}-index")))
    }

    /// The checked index of one archive, building it from one parse of the
    /// archive when there is none on disk or the one there does not check.
    ///
    /// Checked once per process per archive: the archive's SHA-256 is
    /// computed (one read, no parse) and compared with the one the index
    /// was built from, and the index file's own trailer with its bytes.
    /// `None` when no index can be had; the caller scans the archive, as
    /// before Round 28.
    fn archive_index(&self, archive: &Path) -> Option<ArchiveIndex> {
        let len = std::fs::metadata(archive).ok()?.len();
        if let Some(answer) = self.cached_index(archive, len) {
            return answer;
        }
        let _building = match self.index_build.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Another lookup, or a background job, may have checked or built it
        // while this one waited.
        if let Some(answer) = self.cached_index(archive, len) {
            return answer;
        }
        let answer = self.check_or_build_index(archive, len);
        let state = match &answer {
            Some(index) => IndexState::Ready(index.clone()),
            None => {
                // The wait doubles with each failure at this length.
                let failures = match self.archive_indexes.lock() {
                    Ok(g) => previous_failures(g.get(archive), len),
                    Err(poisoned) => previous_failures(poisoned.into_inner().get(archive), len),
                } + 1;
                IndexState::Unavailable {
                    len,
                    failures,
                    retry_at: std::time::Instant::now() + index_retry_wait(failures),
                }
            }
        };
        self.remember_index(archive, state);
        answer
    }

    /// What this process already knows about an archive's index at its
    /// current length: `Some(Some(_))` a checked index, `Some(None)` none to
    /// be had (until its retry is due), `None` not yet looked at or due to
    /// be looked at again.
    fn cached_index(&self, archive: &Path, len: u64) -> Option<Option<ArchiveIndex>> {
        let indexes = match self.archive_indexes.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match indexes.get(archive) {
            Some(IndexState::Ready(index)) if index.archive_len == len => Some(Some(index.clone())),
            Some(IndexState::Unavailable {
                len: at, retry_at, ..
            }) if *at == len && std::time::Instant::now() < *retry_at => Some(None),
            _ => None,
        }
    }

    fn remember_index(&self, archive: &Path, state: IndexState) {
        let mut indexes = match self.archive_indexes.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        indexes.insert(archive.to_path_buf(), state);
    }

    /// Run an index job on its own thread, counted in `index_jobs` until it
    /// returns or panics. A thread that cannot be started leaves the work to
    /// the first lookup that needs it.
    fn spawn_index_job(&self, job: impl FnOnce(&AuditLog) + Send + 'static) {
        struct Done(Arc<AtomicU64>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.index_jobs.fetch_add(1, Ordering::SeqCst);
        let log = self.clone();
        let done = Done(self.index_jobs.clone());
        let spawned = std::thread::Builder::new()
            .name("graphite-audit-index".to_string())
            .spawn(move || {
                // Locals drop in reverse order: the job's clone of the log —
                // and with it any share of the writer lock — is released
                // before the count says the job is done, so a caller that
                // waits for the count to reach zero can reopen the trail.
                let _done = done;
                let log = log;
                job(&log);
            });
        if let Err(e) = spawned {
            // The closure, and its `Done`, were dropped with the error.
            tracing::warn!(
                "audit archive index job could not start ({e}); the first lookup does the work"
            );
        }
    }

    /// Check or build every archive's index, newest first, on a background
    /// thread, after removing index files no archive needs. The server
    /// calls this at start so the first L8 lookup after a restart does not
    /// pay for checking every archive (measured: 1.8 s for three 64 MiB
    /// archives, against 2 ms for an indexed count).
    pub fn warm_archive_indexes_in_background(&self) {
        self.spawn_index_job(|log| {
            log.sweep_index_dir();
            for archive in log.archives().iter().rev() {
                let _ = log.archive_index(archive);
            }
        });
    }

    /// Write a just-rotated archive's index from the indexes the active file
    /// kept while it was written, so nothing is parsed. Used only when those
    /// indexes account for exactly the archive's bytes, the same rule the
    /// active counts are answered by; otherwise the first lookup builds the
    /// index from a parse.
    fn index_rotated_archive(&self, archive: PathBuf, indexes: ActiveIndexes) {
        self.spawn_index_job(move |log| {
            let _building = match log.index_build.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let (last, lifecycle, counts) = indexes;
            let Ok((sha256, len)) = archive_index::file_sha256(&archive) else {
                return;
            };
            if counts.len != len || log.cached_index(&archive, len).is_some() {
                return;
            }
            let Some(index_path) = log
                .index_dir()
                .and_then(|dir| archive_index::index_path(&dir, &archive))
            else {
                return;
            };
            let source = archive_index::IndexSource {
                last: &last,
                counts: &counts.by_key,
                lifecycle: &lifecycle,
            };
            match archive_index::write(&index_path, len, &sha256, source) {
                Ok(index) => log.remember_index(&archive, IndexState::Ready(index)),
                Err(e) => tracing::warn!(
                    "audit archive index {} could not be written ({e}); the first lookup retries",
                    index_path.display()
                ),
            }
        });
    }

    /// Remove index files that describe no archive on disk (pruned while
    /// its index was being written) and temporary files a stopped process
    /// left. Under the build lock, so no file being written is removed.
    fn sweep_index_dir(&self) {
        let Some(dir) = self.index_dir() else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        let _building = match self.index_build.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(log_dir) = self.path.parent() else {
            return;
        };
        let Some(stem) = self.path.file_name().and_then(|s| s.to_str()) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let stale = if name.contains(".idx.tmp-") {
                true
            } else if let Some(archive) = name.strip_suffix(".idx") {
                // Also the index of a file no longer read as an archive
                // (one an earlier version indexed, such as `audit.jsonl.bak`).
                parse_archive_name(stem, archive).is_none() || !log_dir.join(archive).is_file()
            } else {
                false
            };
            if stale {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Wait until no background index job is running (tests).
    #[cfg(test)]
    fn wait_for_index_jobs(&self) {
        let start = std::time::Instant::now();
        while self.index_jobs.load(Ordering::SeqCst) > 0 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(60),
                "background index jobs did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The archive's index, checked or built; `None` when none can be had.
    fn check_or_build_index(&self, archive: &Path, len: u64) -> Option<ArchiveIndex> {
        let unavailable = None;
        let Some(index_path) = self
            .index_dir()
            .and_then(|dir| archive_index::index_path(&dir, archive))
        else {
            return unavailable;
        };
        let Ok((sha256, hashed_len)) = archive_index::file_sha256(archive) else {
            return unavailable;
        };
        if hashed_len != len {
            return unavailable;
        }
        if let Some(index) = archive_index::open_checked(&index_path, len, &sha256) {
            return Some(index);
        }
        if index_path.exists() {
            tracing::warn!(
                "audit archive index {} does not check against its archive; rebuilding it",
                index_path.display()
            );
        }
        self.archive_index_builds.fetch_add(1, Ordering::Relaxed);
        let (last, lifecycle, counts) = build_indexes(archive);
        // The parse must have read the bytes that were hashed.
        if counts.len != len {
            return unavailable;
        }
        let source = archive_index::IndexSource {
            last: &last,
            counts: &counts.by_key,
            lifecycle: &lifecycle,
        };
        match archive_index::write(&index_path, len, &sha256, source) {
            Ok(index) => Some(index),
            Err(e) => {
                tracing::warn!(
                    "audit archive index {} could not be written ({e}); that archive is scanned on each lookup until a retry succeeds",
                    index_path.display()
                );
                unavailable
            }
        }
    }

    /// Forget an archive's index after it answered something its archive
    /// does not hold, and remove the file, so the next lookup checks the
    /// archive again and rebuilds.
    fn discard_archive_index(&self, archive: &Path) {
        if let Ok(mut indexes) = self.archive_indexes.lock() {
            indexes.remove(archive);
        }
        if let Some(path) = self
            .index_dir()
            .and_then(|dir| archive_index::index_path(&dir, archive))
        {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Build a UNIQUE archive path for a rotation occurring at wall-clock
    /// millisecond `now`.
    ///
    /// Split out from `rotate_if_needed` specifically so it can be tested with
    /// a FIXED stamp. The bug this guards against — two rotations in the same
    /// millisecond producing the same filename, with `fs::rename` then
    /// silently destroying the first archive — only reproduces when rotations
    /// are fast enough to share a millisecond. That makes any test driving it
    /// through real writes dependent on filesystem speed: the original test
    /// passed on a Windows dev machine (~4ms per rotation, measured) while
    /// Linux CI lost 126 of 150 records. A test calling this directly with the
    /// same stamp twice reproduces the collision deterministically on every
    /// platform.
    ///
    /// The stamp is not `now` itself but the largest of `now`, the newest
    /// archive's stamp plus one and this process's last stamp plus one
    /// (Round 29, audit 2026-10-20):
    /// archives are ordered by stamp first, and a wall clock stepped back
    /// would otherwise name the next archive older than the newest one, so
    /// pruning deleted the newest and newest-first lookups read the trail
    /// out of order. Strictly increasing stamps make the order the order of
    /// creation whatever the clock does, across restarts too (the newest
    /// archive on disk carries the floor). The sequence is kept in the name
    /// for compatibility with archives already on disk, and zero-padded as
    /// before.
    ///
    /// An error when every probed name exists: renaming onto one would
    /// replace an archive. It used to give up after 10,000 probes and return
    /// the last name, which `rotate_if_needed` then renamed over.
    fn next_archive_path(&self, now: u128) -> std::io::Result<PathBuf> {
        let newest_on_disk = self
            .archives_ordered()
            .last()
            .map(|((stamp, _, _), _)| *stamp);
        let stamp = {
            let mut last = match self.last_stamp.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let floor = [newest_on_disk, *last]
                .into_iter()
                .flatten()
                .max()
                .map(|s| s.saturating_add(1))
                .unwrap_or(0);
            let stamp = now.max(floor);
            if stamp > now {
                tracing::warn!(
                    "audit archive stamp {stamp} is ahead of the wall clock ({now} ms): the clock stepped back or rotations outpaced it; archives stay in creation order"
                );
            }
            *last = Some(stamp);
            stamp
        };
        let seq = self.rotation_seq.fetch_add(1, Ordering::Relaxed);
        let mut archive = self
            .path
            .with_extension(format!("jsonl.{stamp}-{seq:06}"))
            .to_path_buf();

        // Cross-restart safety: the stamp is above every archive name this
        // log generated, so a collision means a file this log did not write
        // (or another process writing the same log). Probing is safe here
        // (callers hold the append handle lock, so nothing in this process
        // can race us) and costs one stat on a path taken once per rotation.
        let mut extra = 0u32;
        while archive.exists() {
            if extra == MAX_ARCHIVE_NAME_PROBES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "every archive name for stamp {stamp}, sequence {seq} already exists ({MAX_ARCHIVE_NAME_PROBES} probed)"
                    ),
                ));
            }
            extra += 1;
            archive = self
                .path
                .with_extension(format!("jsonl.{stamp}-{seq:06}-{extra:04}"))
                .to_path_buf();
        }
        Ok(archive)
    }

    /// Open (creating) the active file for appending.
    fn open_active(&self) -> std::io::Result<File> {
        if self.injected(FAULT_REOPEN) {
            return Err(std::io::Error::other("injected: reopen fails"));
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.as_ref())
    }

    /// Hand the active file's indexes to the archive it was just renamed
    /// to, and note the rotation. The active indexes are empty afterwards.
    fn retire_active_indexes(&self, archive: &Path) {
        // Every offset the index holds points into the archive, and becomes
        // the archive's own index (R-M11).
        let last = match self.active_index.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        let lifecycle = match self.lifecycle_index.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        // The fresh file holds nothing and accounts for zero bytes; the
        // rotated records are counted from the archive.
        let counts = match self.active_counts.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        self.index_rotated_archive(archive.to_path_buf(), (last, lifecycle, counts));
        match self.last_rotation.lock() {
            Ok(mut g) => *g = Some(std::time::Instant::now()),
            Err(poisoned) => *poisoned.into_inner() = Some(std::time::Instant::now()),
        }
    }

    /// Rotate the active file if it has grown past `rotate_bytes`.
    ///
    /// Called with the append handle already locked, so no writer can append
    /// between the size check and the rename. The rename preserves every
    /// record (P9 — rotation is not deletion); only explicit `max_archives`
    /// pruning removes anything, and that is opt-in.
    fn rotate_if_needed(&self, file: &mut File) {
        if self.rotate_bytes == 0 {
            return;
        }
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => return,
        };
        if size < self.rotate_bytes {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // If no name can be had, or the rename fails (permissions,
        // cross-device, another process holding the file without
        // delete-sharing), keep appending to the current file rather than
        // losing the record — an oversized log is strictly better than a
        // dropped audit trail. It is retried on the next append and COUNTED,
        // so /health shows a log that cannot rotate instead of one that
        // merely looks large.
        //
        // The rename happens with our own append handle still open. That is
        // fine on every platform Rust's std supports: on Unix a rename never
        // cares about open descriptors, and on Windows `OpenOptions` opens
        // with `FILE_SHARE_DELETE`, under which `MoveFileEx` succeeds on an
        // open file (verified by `active_audit_file_is_bounded_by_rotation`
        // running on NTFS). What breaks it is a FOREIGN handle without that
        // share mode — `rotation_failure_is_counted_and_never_drops_a_record`
        // reproduces exactly that.
        let renamed = self.next_archive_path(now).and_then(|archive| {
            if self.injected(FAULT_ROTATE_RENAME) {
                return Err(std::io::Error::other("injected: rotation rename fails"));
            }
            std::fs::rename(self.path.as_ref(), &archive).map(|_| archive)
        });
        let archive = match renamed {
            Ok(archive) => archive,
            Err(e) => {
                let n = self.rotations_failed.fetch_add(1, Ordering::Relaxed) + 1;
                // Once per failure would page on every append; log the first
                // and then every 1000th so the condition stays visible
                // without flooding.
                if n == 1 || n.is_multiple_of(1000) {
                    tracing::error!(
                        "audit rotation failed ({n} times): {e}; the active file keeps growing"
                    );
                }
                return;
            }
        };
        match self.open_active() {
            Ok(fresh) => {
                *file = fresh;
                self.retire_active_indexes(&archive);
                // The rename and the new file are directory entries; make
                // them durable so a crash right after rotation cannot lose
                // the archive's NAME while its data survives.
                sync_dir(self.path.as_ref());
                self.rotations_ok.fetch_add(1, Ordering::Relaxed);
                tracing::info!("audit log rotated to {}", archive.display());
                self.write_anchor();
                self.prune_archives();
            }
            Err(e) => {
                self.rotations_failed.fetch_add(1, Ordering::Relaxed);
                // We already renamed the old file away; try to restore it so
                // no window exists with no audit file at all. The append
                // handle still points at that file, so a successful rename
                // back leaves everything as it was before the rotation.
                let restored = if self.injected(FAULT_RENAME_BACK) {
                    Err(std::io::Error::other("injected: rename back fails"))
                } else {
                    std::fs::rename(&archive, self.path.as_ref())
                };
                match restored {
                    Ok(()) => {
                        tracing::error!("audit rotation failed to reopen log: {e}; rotation undone")
                    }
                    Err(back) => {
                        // Round 29 (audit 2026-10-20, audit trail): the handle
                        // now writes into the archive. Appends through it
                        // would grow a file every reader treats as immutable;
                        // they are refused until a fresh active file opens
                        // (`reattach`). The archive is an archive: its
                        // records leave the active indexes with it.
                        self.retire_active_indexes(&archive);
                        sync_dir(self.path.as_ref());
                        match self.detached_into.lock() {
                            Ok(mut g) => *g = Some(archive.clone()),
                            Err(poisoned) => *poisoned.into_inner() = Some(archive.clone()),
                        }
                        tracing::error!(
                            "audit rotation failed to reopen log ({e}) and to undo the rename ({back}); the trail continues in {} and appends are REFUSED until {} can be created",
                            archive.display(),
                            self.path.display()
                        );
                    }
                }
            }
        }
    }

    /// When a failed rotation left the append handle pointing into an
    /// archive (`detached_into`), try once more to open a fresh active
    /// file. `Err` while there is still none: the caller refuses the append.
    fn reattach(&self, file: &mut File) -> Result<(), ()> {
        let mut detached = match self.detached_into.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(archive) = detached.clone() else {
            return Ok(());
        };
        match self.open_active() {
            Ok(fresh) => {
                *file = fresh;
                *detached = None;
                drop(detached);
                sync_dir(self.path.as_ref());
                // Whatever the new active file holds (normally nothing) is
                // what its indexes describe.
                let (last, lifecycle, counts) = build_indexes(self.path.as_ref());
                match self.active_index.lock() {
                    Ok(mut g) => *g = last,
                    Err(poisoned) => *poisoned.into_inner() = last,
                }
                match self.lifecycle_index.lock() {
                    Ok(mut g) => *g = lifecycle,
                    Err(poisoned) => *poisoned.into_inner() = lifecycle,
                }
                match self.active_counts.lock() {
                    Ok(mut g) => *g = counts,
                    Err(poisoned) => *poisoned.into_inner() = counts,
                }
                self.torn_tail
                    .store(ends_without_newline(self.path.as_ref()), Ordering::SeqCst);
                tracing::warn!(
                    "audit log {} reopened; {} is an archive again and appends resume",
                    self.path.display(),
                    archive.display()
                );
                self.prune_archives();
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    "audit append refused: {} still cannot be created ({e}); not appending to the archive {}",
                    self.path.display(),
                    archive.display()
                );
                Err(())
            }
        }
    }

    /// Cut the active file back to `len` bytes and sync it: the bytes after
    /// `len` belong to an append that was not acknowledged.
    ///
    /// Through a handle of its own: the append handle may be append-only,
    /// and on Windows such a handle cannot set the end of file.
    fn truncate_active(&self, len: u64) -> std::io::Result<()> {
        if self.injected(FAULT_TRUNCATE) {
            return Err(std::io::Error::other("injected: truncation fails"));
        }
        let f = OpenOptions::new().write(true).open(self.path.as_ref())?;
        if f.metadata()?.len() > len {
            f.set_len(len)?;
        }
        f.sync_data()
    }

    /// Prune the oldest archives when an explicit retention limit is set.
    /// No-op when `max_archives == 0` (keep everything — the P9 default).
    fn prune_archives(&self) {
        if self.max_archives == 0 {
            return;
        }
        let mut archives = self.archives();
        let pruned = archives.len() > self.max_archives;
        while archives.len() > self.max_archives {
            let oldest = archives.remove(0);
            if let Err(e) = std::fs::remove_file(&oldest) {
                tracing::warn!("audit archive prune failed for {}: {}", oldest.display(), e);
            } else if let Some(index) = self
                .index_dir()
                .and_then(|dir| archive_index::index_path(&dir, &oldest))
            {
                // An index outlives nothing it describes.
                let _ = std::fs::remove_file(index);
            }
        }
        self.forget_missing_archives(&archives);
        // An index being written while its archive was pruned can land
        // after the removal above; the sweep removes it.
        if pruned {
            self.spawn_index_job(|log| log.sweep_index_dir());
        }
    }

    /// The most recent `tail` records the selector keeps, oldest-first, from
    /// the WHOLE trail: every rotated archive and the active file.
    ///
    /// Returns `(records, error_records, total_records, total_errors)`. The
    /// totals are exact over the whole trail. The records retained are
    /// bounded by `tail`, and one file's scan by that file's size. Each
    /// archive's statistics stay cached for the life of the process (they
    /// are what spares the rescans): a few counters plus at most
    /// `MAX_PROGRAMS_PER_ARCHIVE` program counts per archive, so the cache
    /// grows with the number of archives on disk and with nothing a caller
    /// chooses. `tail == 0` retains nothing and still reports exact totals.
    ///
    /// Cost: the active file is scanned on every call — it is bounded by
    /// rotation, which is what rotation is for. An archive is scanned at
    /// most once for its statistics (cached; archives are immutable) and
    /// again only when its records are needed because the newer files did
    /// not hold `tail` of them. So a dashboard poll on a long-running node
    /// reads the active file plus, occasionally, the newest archive — never
    /// the whole history.
    ///
    /// Malformed lines (a torn final line from a crash mid-write) and
    /// lifecycle-event lines are skipped, never an error.
    pub fn read_tail_filtered(
        &self,
        tail: usize,
        selector: AuditSelector,
    ) -> (Vec<AuditRecord>, Vec<AuditErrorRecord>, usize, usize) {
        let (archives, active) = self.snapshot();
        self.forget_missing_archives(&archives);

        // Newest first: the active file, then archives from the newest back.
        // Each file contributes its last records ahead of everything older,
        // so the result is assembled from the newest end and older files are
        // opened for records only while there is still room.
        let mut records: VecDeque<AuditRecord> = VecDeque::new();
        let mut errors: VecDeque<AuditErrorRecord> = VecDeque::new();
        let mut total_records = 0usize;
        let mut total_errors = 0usize;

        let take = |scan: FileScan,
                    records: &mut VecDeque<AuditRecord>,
                    errors: &mut VecDeque<AuditErrorRecord>| {
            // Prepend this (older) file's newest records under the ones
            // already collected, keeping the overall newest `tail`.
            for r in scan.records.into_iter().rev() {
                if records.len() == tail {
                    break;
                }
                records.push_front(r);
            }
            for e in scan.errors.into_iter().rev() {
                if errors.len() == tail {
                    break;
                }
                errors.push_front(e);
            }
        };

        if let Some((file, len)) = active {
            let scan = scan_file(file, len, tail, selector);
            total_records += scan.stats.records(selector);
            total_errors += scan.stats.errors;
            take(scan, &mut records, &mut errors);
        }
        for archive in archives.iter().rev() {
            let room_for_records = records.len() < tail;
            let room_for_errors = errors.len() < tail;
            let need_records = |stats: &ArchiveStats| {
                (room_for_records && stats.records(selector) > 0)
                    || (room_for_errors && stats.errors > 0)
            };
            let Some((stats, scan)) = self.archive_scan(archive, tail, selector, need_records)
            else {
                continue;
            };
            total_records += stats.records(selector);
            total_errors += stats.errors;
            if let Some(scan) = scan {
                take(scan, &mut records, &mut errors);
            }
        }
        (records.into(), errors.into(), total_records, total_errors)
    }

    /// The most recent verification record for `content_hash`, from the whole
    /// trail.
    ///
    /// This is what L8 reconciliation joins on. It walks newest-first and
    /// stops at the first file holding a match, taking the LAST match in that
    /// file: a caller may verify the same transaction more than once, and the
    /// decision that governed is the most recent one before submission.
    ///
    /// Not cached, and deliberately not a selector: a content hash is chosen
    /// per call, and this lookup is rare (once per execution audit) compared
    /// with the dashboard's polling.
    pub fn last_verification_for(&self, content_hash: &str) -> Option<AuditRecord> {
        self.find_verification(VerificationKey::ContentHash(content_hash))
    }

    /// How many verifications the trail holds for `key`, split by verdict:
    /// `(approved, refused)`. Whole trail — active file and every archive.
    ///
    /// Round 17 (F-16-11): `find_verification` answers with the LAST record
    /// for a key, so the same artifact refused once and approved later
    /// reconciled as approved with no sign that a refusal existed. L8 now
    /// reports these counts beside the record it resolved.
    ///
    /// The active file's share comes from `active_counts` (Round 22): it was
    /// a substring pass over the whole active file on every L8 lookup with a
    /// chain digest. Each archive's share comes from its persisted index
    /// (R-M11, Round 28); an archive without one is scanned.
    pub fn count_verifications(&self, key: VerificationKey<'_>) -> (usize, usize) {
        let wanted = key.value().trim();
        if wanted.is_empty() {
            return (0, 0);
        }
        let mut approved = 0usize;
        let mut refused = 0usize;
        let tally = |file: &mut dyn std::io::Read| {
            let (mut approved, mut refused) = (0usize, 0usize);
            for_each_line(file, |line| {
                if !line.contains(wanted) {
                    return;
                }
                if let Ok(r) = serde_json::from_str::<AuditRecord>(line) {
                    if key.matches(&r) {
                        if r.approved {
                            approved += 1;
                        } else {
                            refused += 1;
                        }
                    }
                }
            });
            (approved, refused)
        };
        // The active file, from the counts, under the append lock so no write
        // can land between reading the file's length and reading the counts
        // (Round 22). The counts are used only when they account for exactly
        // the bytes the file holds; otherwise — a write that failed part-way,
        // a file changed by something other than this log — the active file
        // is recounted, the counts replaced by what it holds, and the
        // disagreement logged. Never an answer from counts the file
        // contradicts. The archives are immutable and answer from their
        // indexes.
        let (archives, active) = {
            let file = match self.file.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Bytes an append could not acknowledge are not counted
            // (`unacknowledged_from`), and while the handle writes into an
            // archive the records it holds are counted as that archive's.
            let actual = if self.is_detached() {
                Some(0)
            } else {
                file.metadata().map(|m| self.acknowledged_len(m.len())).ok()
            };
            let mut counts = match self.active_counts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if actual != Some(counts.len) {
                tracing::error!(
                    "audit counts: they account for {} bytes of the active file, which holds {actual:?}; recounting the active file",
                    counts.len
                );
                self.active_count_scans.fetch_add(1, Ordering::Relaxed);
                *counts = build_indexes_upto(self.path.as_ref(), actual.unwrap_or(u64::MAX)).2;
            }
            let active = counts
                .by_key
                .get(&key.index_key())
                .copied()
                .unwrap_or((0, 0));
            drop(counts);
            // Listed under the append lock too: a rotation between the count
            // and the listing would count the rotated records twice.
            let archives = self.archives();
            drop(file);
            (archives, active)
        };
        let index_key = key.index_key();
        for archive in archives {
            if let Some(index) = self.archive_index(&archive) {
                match index.verification(&index_key) {
                    Ok(Some(entry)) if index_entry_is_plausible(&archive, &index, &entry, &key) => {
                        approved += entry.approved as usize;
                        refused += entry.refused as usize;
                        continue;
                    }
                    Ok(Some(entry)) => {
                        tracing::error!(
                            "audit archive index for {}: the entry for {wanted} ({} approved, {} refused, last at {}) does not agree with the archive; scanning the archive",
                            archive.display(),
                            entry.approved,
                            entry.refused,
                            entry.last_offset
                        );
                        self.discard_archive_index(&archive);
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::error!(
                            "audit archive index for {} could not be read ({e}); scanning the archive",
                            archive.display()
                        );
                        self.discard_archive_index(&archive);
                    }
                }
            }
            self.archive_scans.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut file) = File::open(&archive) {
                let (a, r) = tally(&mut file);
                approved += a;
                refused += r;
            }
        }
        (approved + active.0, refused + active.1)
    }

    /// The most recent verification record under `key`, from the whole
    /// trail — the active file by index, then the archives newest-first.
    ///
    /// `AuditTrailId` is exact (one verification). `TransactionSha256` is
    /// exact about the bytes and newest-first about the decision, which is
    /// the decision that governed at submission. `ContentHash` is the
    /// instruction-level key and answers for whichever transaction carrying
    /// that instruction was verified last; callers that have a better key
    /// must use it (Round 10).
    pub fn find_verification(&self, key: VerificationKey<'_>) -> Option<AuditRecord> {
        let wanted = key.value().trim();
        if wanted.is_empty() {
            return None;
        }
        let index_key = key.index_key();
        let find_in = |file: &mut dyn std::io::Read| -> Option<AuditRecord> {
            let mut last = None;
            for_each_line(file, |line| {
                // A line that does not contain the hash cannot be its
                // record; the substring test is the cheap filter in front of
                // the JSON parse.
                if !line.contains(wanted) {
                    return;
                }
                if let Ok(r) = serde_json::from_str::<AuditRecord>(line) {
                    if key.matches(&r) {
                        last = Some(r);
                    }
                }
            });
            last
        };
        // The active file, by index, under the append lock so the offset
        // cannot go stale between the lookup and the read. An indexed hash
        // whose line does not read back is a corrupted active file (or a
        // bug in the index): the whole active file is scanned rather than
        // answering from a broken index, and the failure is logged.
        let archives = {
            let _guard = match self.file.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let offset = match self.active_index.lock() {
                Ok(g) => g.get(&index_key).copied(),
                Err(poisoned) => poisoned.into_inner().get(&index_key).copied(),
            };
            if let Some(offset) = offset {
                let indexed = File::open(self.path.as_ref()).ok().and_then(|mut file| {
                    use std::io::Seek;
                    let mut line = String::new();
                    file.seek(std::io::SeekFrom::Start(offset)).ok()?;
                    BufReader::new(file).read_line(&mut line).ok()?;
                    serde_json::from_str::<AuditRecord>(line.trim_end())
                        .ok()
                        .filter(|r| key.matches(r))
                });
                if indexed.is_some() {
                    return indexed;
                }
                tracing::error!(
                    "audit index: offset {offset} for {wanted} did not read back as its record; scanning the active file"
                );
                self.active_lookup_scans.fetch_add(1, Ordering::Relaxed);
                // Only the acknowledged bytes: a record an append could not
                // acknowledge is not one Graphite stands behind.
                let found = File::open(self.path.as_ref()).ok().and_then(|f| {
                    use std::io::Read;
                    let len = self.acknowledged_len(f.metadata().ok()?.len());
                    find_in(&mut f.take(len))
                });
                if found.is_some() {
                    return found;
                }
            }
            self.archives()
        };
        // Not in the active file. The archives are immutable and searched
        // newest-first, each by its index (R-M11, Round 28). An indexed
        // offset is read back from the archive and matched before it is an
        // answer; one that does not read back discards the index and scans
        // the archive, never answering from a broken index.
        for archive in archives.iter().rev() {
            if let Some(index) = self.archive_index(archive) {
                match index.verification(&index_key) {
                    Ok(None) => continue,
                    Ok(Some(entry)) => {
                        if let Some(r) =
                            read_record_at(archive, entry.last_offset).filter(|r| key.matches(r))
                        {
                            return Some(r);
                        }
                        tracing::error!(
                            "audit archive index: offset {} for {wanted} did not read back as its record in {}; scanning the archive",
                            entry.last_offset,
                            archive.display()
                        );
                    }
                    Err(e) => tracing::error!(
                        "audit archive index for {} could not be read ({e}); scanning the archive",
                        archive.display()
                    ),
                }
                self.discard_archive_index(archive);
            }
            self.archive_scans.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut file) = File::open(archive) {
                if let Some(r) = find_in(&mut file) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Per-program observation counts over the whole trail — used by
    /// `/api/protocols/top`, which shows the five largest.
    ///
    /// Exact for the active file. Each archive contributes its
    /// `MAX_PROGRAMS_PER_ARCHIVE` most frequent programs (from the cache
    /// after its first scan); a program outside an archive's top is not
    /// counted for that archive, so a long-tail program's count can be
    /// short, and the top programs' counts are exact. The result holds at
    /// most the active file's distinct programs plus that many per archive.
    pub fn observations_by_program(&self) -> HashMap<String, usize> {
        let (archives, active) = self.snapshot();
        self.forget_missing_archives(&archives);
        let mut counts: HashMap<String, usize> = HashMap::new();
        if let Some((file, len)) = active {
            let scan = scan_file(file, len, 0, AuditSelector::All);
            for (program, n) in scan.stats.by_program {
                *counts.entry(program).or_insert(0) += n;
            }
        }
        for archive in &archives {
            if let Some((stats, _)) = self.archive_scan(archive, 0, AuditSelector::All, |_| false) {
                for (program, n) in stats.by_program {
                    *counts.entry(program).or_insert(0) += n;
                }
            }
        }
        counts
    }

    /// Append a verification record. Returns whether it is durably on disk.
    ///
    /// The return value used to be `()`. Failures were counted and otherwise
    /// invisible, so a caller could not tell an approval that was recorded from
    /// one that was not — and the verify handler, which is the caller that
    /// matters, went on to answer with a clean approval either way (found in an
    /// independent review of `main`, 2026-09-08).
    ///
    /// That is an integrity failure rather than an observability one. Graphite's
    /// value depends on the append-only trail existing: "Graphite approved X"
    /// and "there is no durable record that Graphite approved X" cannot both be
    /// acceptable in a system whose L8 reconciliation, quarantine decisions and
    /// incident response all read that trail.
    #[must_use]
    pub fn append(&self, record: &AuditRecord) -> bool {
        self.append_line_with(record, &index_keys(record), &[], Some(record.approved))
    }

    /// Append an error-path record (same durability contract).
    pub fn append_error(&self, record: &AuditErrorRecord) -> bool {
        self.append_line(&record.bounded())
    }

    /// Append a lifecycle event (P9). Same durability contract as `append`:
    /// synced before the caller is answered, non-fatal on failure but
    /// counted, and subject to the same rotation.
    ///
    /// Bounded like the error record (Round 9): every field of this record
    /// is caller-supplied, and until this was bounded a single
    /// `POST /audit/event` could put a megabyte of chosen bytes on the
    /// operator's audit volume — 64 of them forced a rotation, and with
    /// `GRAPHITE_AUDIT_MAX_ARCHIVES` set, rotations prune the oldest archive
    /// of REAL verifications. The 2026-09-06 fix bounded the error record and
    /// the entry-point identifiers; this record type was added after it and
    /// was not covered.
    pub fn append_lifecycle(&self, record: &LifecycleEventRecord) -> bool {
        let bounded = record.bounded();
        let keys = bounded.lifecycle_keys();
        self.append_line_with(&bounded, &[], &keys, None)
    }

    /// Every lifecycle row on record for a transaction, in file order:
    /// the newest archive's rows first when the active file rotated within
    /// `ROTATION_STRADDLE_WINDOW` (a lifecycle that straddled the rotation
    /// has rows on both sides — Round 17, F-15-09; until then the archive
    /// was consulted only when the active file held NO row, so a straddling
    /// lifecycle was reconstructed from the active side alone and produced
    /// false sequence anomalies), then the active file by index.
    ///
    /// Bounded at `MAX_LIFECYCLE_HISTORY` rows. Older archives are not
    /// consulted: a transaction's lifecycle spans seconds to minutes and an
    /// archive spans 64 MB of records, so a lifecycle across two rotations
    /// is not one this lookup claims to reconstruct — a documented limit,
    /// not a silent one (Round 12).
    pub fn lifecycle_history(&self, key: LifecycleKey<'_>) -> Vec<LifecycleEventRecord> {
        if key.is_empty() {
            return Vec::new();
        }
        let rotated_recently = match self.last_rotation.lock() {
            Ok(g) => g.is_some_and(|t| t.elapsed() <= ROTATION_STRADDLE_WINDOW),
            Err(poisoned) => poisoned
                .into_inner()
                .is_some_and(|t| t.elapsed() <= ROTATION_STRADDLE_WINDOW),
        };
        let (rows, newest_archive) = {
            let _guard = match self.file.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let mut offsets: Vec<u64> = {
                let index = match self.lifecycle_index.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                key.index_keys()
                    .iter()
                    .filter_map(|k| index.get(k))
                    .flatten()
                    .copied()
                    .collect()
            };
            offsets.sort_unstable();
            offsets.dedup();
            // The union of several keys' rows is bounded like one key's:
            // first rows kept, latest rows kept (Round 19, F-19-20). Keeping
            // only the first 64 let rows filed under one key push another
            // key's newest row out of the merged view.
            let offsets = bound_history(offsets);
            let mut rows = Vec::with_capacity(offsets.len());
            if !offsets.is_empty() {
                if let Ok(mut file) = File::open(self.path.as_ref()) {
                    use std::io::Seek;
                    for offset in offsets {
                        let mut line = String::new();
                        if file.seek(std::io::SeekFrom::Start(offset)).is_err() {
                            continue;
                        }
                        let mut reader = BufReader::new(&mut file);
                        if reader.read_line(&mut line).is_err() {
                            continue;
                        }
                        match lifecycle_row(line.trim_end().as_bytes()) {
                            Some(r) if key.matches(&r) => rows.push(r),
                            _ => tracing::error!(
                                "audit lifecycle index: offset {offset} did not read back as a row for its key"
                            ),
                        }
                    }
                }
            }
            (rows, self.archives().last().cloned())
        };
        // The archive is scanned when the active file holds nothing for the
        // key (the pre-Round-17 rule) OR the rotation is recent enough that
        // a lifecycle in progress may have rows on both sides of it.
        if !rows.is_empty() && !rotated_recently {
            return rows;
        }
        let Some(archive) = newest_archive else {
            return rows;
        };
        // The archive's rows, by its index (R-M11, Round 28) when it has
        // one and every indexed row reads back as a row for this key.
        if let Some(mut found) = self.lifecycle_rows_from_index(&archive, &key) {
            found.extend(rows);
            return bound_history(found);
        }
        self.archive_scans.fetch_add(1, Ordering::Relaxed);
        let Ok(file) = File::open(&archive) else {
            return rows;
        };
        let mut found = Vec::new();
        let mut reader = BufReader::new(file);
        let mut line: Vec<u8> = Vec::new();
        loop {
            line.clear();
            let Ok(n) = reader.read_until(b'\n', &mut line) else {
                break;
            };
            if n == 0 {
                break;
            }
            if let Some(r) = lifecycle_row(&line) {
                if key.matches(&r) {
                    found.push(r);
                    // Stay bounded while reading a large archive.
                    if found.len() > 2 * MAX_LIFECYCLE_HISTORY {
                        found = bound_history(found);
                    }
                }
            }
        }
        // Archive rows precede active rows in time. The bound keeps the
        // earliest rows and the NEWEST ones — the active file's — rather
        // than truncating the newest away.
        found.extend(rows);
        bound_history(found)
    }

    /// An archive's lifecycle rows for `key`, from its index, bounded like a
    /// scan's. `None` when the archive has no checked index or an indexed
    /// row does not read back as a row for the key; that index is discarded
    /// and the caller scans.
    ///
    /// Each key's offsets were bounded when the index was built
    /// (`push_lifecycle_offset`: the first rows kept, the latest rolling),
    /// and the union of bounded lists, bounded again, keeps the same rows
    /// as bounding the union of every row: each of the union's first and
    /// last rows is among the first or last rows of its own key.
    fn lifecycle_rows_from_index(
        &self,
        archive: &Path,
        key: &LifecycleKey<'_>,
    ) -> Option<Vec<LifecycleEventRecord>> {
        let index = self.archive_index(archive)?;
        let mut offsets = Vec::new();
        for k in key.index_keys() {
            match index.lifecycle_offsets(&k) {
                Ok(found) => offsets.extend(found),
                Err(e) => {
                    tracing::error!(
                        "audit archive index for {} could not be read ({e}); scanning the archive",
                        archive.display()
                    );
                    self.discard_archive_index(archive);
                    return None;
                }
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        let offsets = bound_history(offsets);
        let mut rows = Vec::with_capacity(offsets.len());
        if offsets.is_empty() {
            return Some(rows);
        }
        let mut file = File::open(archive).ok()?;
        for offset in offsets {
            use std::io::Seek;
            let mut line = String::new();
            let read = file
                .seek(std::io::SeekFrom::Start(offset))
                .and_then(|_| BufReader::new(&mut file).read_line(&mut line));
            match read
                .ok()
                .and_then(|_| lifecycle_row(line.trim_end().as_bytes()))
            {
                Some(r) if key.matches(&r) => rows.push(r),
                _ => {
                    tracing::error!(
                        "audit archive index: lifecycle offset {offset} in {} did not read back as a row for its key; scanning the archive",
                        archive.display()
                    );
                    self.discard_archive_index(archive);
                    return None;
                }
            }
        }
        Some(rows)
    }

    /// Returns true when the line is written AND synced to the storage device.
    ///
    /// `sync_data`, not `flush`. `std::fs::File` is unbuffered, so its
    /// `flush` is a no-op that returns `Ok(())` without a system call — the
    /// previous code called it and then reported the record as "durably on
    /// disk", which was true only of the operating system's page cache. A
    /// process crash would not have lost the record; a power loss or kernel
    /// panic between the write and the next write-back would, and the caller
    /// had already been told the approval was recorded. `sync_data` is
    /// `fdatasync` / `FlushFileBuffers`: the data is on the device (or in its
    /// battery-backed cache) when it returns. The cost is one device sync per
    /// audit record; `audit_append_syncs_the_device` measures it so the
    /// number in the report is observed, not assumed.
    fn append_line<T: serde::Serialize>(&self, record: &T) -> bool {
        self.append_line_with(record, &[], &[], None)
    }

    /// `append_line`, recording every entry of `index_keys` → this line's
    /// offset in the active index when the write succeeds, every entry of
    /// `lifecycle_keys` in the lifecycle index (Round 12), and — for a
    /// verification record, whose verdict is `verdict` — one more record per
    /// key in the active counts. The offset is the file's length before the
    /// write, read under the same lock the write holds, so no other writer
    /// can interleave between the two.
    ///
    /// Every successful write, indexed or not, advances the bytes the counts
    /// account for by exactly what it wrote. A failed one is undone: the
    /// file is cut back to its length before the write (Round 29, audit
    /// 2026-10-20), so a record reported as not recorded is not in the trail
    /// for any reader, in this process or after a restart. When even the
    /// cut fails, the bytes after that length are excluded from every read
    /// and every later append is refused until the cut succeeds
    /// (`unacknowledged_from`).
    fn append_line_with<T: serde::Serialize>(
        &self,
        record: &T,
        index_keys: &[String],
        lifecycle_keys: &[String],
        verdict: Option<bool>,
    ) -> bool {
        if self.read_only {
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
            tracing::error!(
                "audit append refused: {} was opened read-only",
                self.path.display()
            );
            return false;
        }
        let fields = match serde_json::to_value(record) {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => {
                tracing::error!("audit serialization failed: a record is not a JSON object");
                self.writes_failed.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            Err(e) => {
                tracing::error!("audit serialization failed: {}", e);
                self.writes_failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return false;
            }
        };
        let mut file = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Sealed under the append lock, so the head it extends is the one
        // the previous acknowledged record left (Round 30, G-07).
        let (line, next_head) = chain::seal(fields, &self.chain_head_now(), self.key.as_deref());
        // Never append through a handle that writes into an archive.
        if self.reattach(&mut file).is_err() {
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Never append after bytes that were not acknowledged: the next
        // record would make them look like part of the trail.
        let unacknowledged = self.unacknowledged_from.load(Ordering::SeqCst);
        if unacknowledged != NO_UNACKNOWLEDGED_BYTES {
            if let Err(e) = self.truncate_active(unacknowledged) {
                self.writes_failed.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    "audit append refused: the bytes of {} from offset {unacknowledged} belong to a write that was reported as failed and still cannot be removed ({e})",
                    self.path.display()
                );
                return false;
            }
            self.unacknowledged_from
                .store(NO_UNACKNOWLEDGED_BYTES, Ordering::SeqCst);
            self.torn_tail.store(false, Ordering::SeqCst);
            tracing::warn!(
                "audit log {}: the unacknowledged bytes from offset {unacknowledged} were removed; appends resume",
                self.path.display()
            );
        }
        // The newline written to end a torn tail, when this call writes one.
        let mut terminated_tail: u64 = 0;
        if self.torn_tail.load(Ordering::SeqCst) {
            if let Err(e) = file.write_all(b"\n").and_then(|_| file.sync_data()) {
                self.writes_failed.fetch_add(1, Ordering::Relaxed);
                tracing::error!("audit write failed (terminating a partial line): {}", e);
                return false;
            }
            self.torn_tail.store(false, Ordering::SeqCst);
            terminated_tail = 1;
        }
        // Where this record starts: its offset for the indexes, and the
        // length a failed write is cut back to.
        let start = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                // Without it a failed write could not be undone.
                self.writes_failed.fetch_add(1, Ordering::Relaxed);
                tracing::error!("audit write refused: the active file's length is unknown ({e})");
                return false;
            }
        };
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        // One write of the whole line, newline included: the newline used to
        // be a write of its own, so a failure between the two left a whole
        // JSON record with no end.
        let written = file.write_all(&bytes).and_then(|_| {
            if self.injected(FAULT_SYNC) {
                Err(std::io::Error::other("injected: sync fails"))
            } else {
                file.sync_data()
            }
        });
        if let Err(e) = written {
            // Counted AND reported. The comment here used to say a failing
            // audit disk "must not take down verification", and that reasoning
            // is right for the process — the server should stay up — but wrong
            // for the individual answer. A verdict Graphite cannot record is a
            // verdict it should not hand back as though it had.
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
            // Any of the line may have landed, all of it included (a failed
            // sync says nothing about the write before it). Undo it, so that
            // what this call reports as not recorded is not in the trail.
            match self.truncate_active(start) {
                Ok(()) => tracing::error!(
                    "audit write failed: {e}; the {} bytes it may have left were removed",
                    bytes.len()
                ),
                Err(undo) => {
                    self.unacknowledged_from.store(start, Ordering::SeqCst);
                    tracing::error!(
                        "audit write failed: {e}; its bytes could not be removed ({undo}). {} from offset {start} is NOT a record Graphite acknowledged: readers in this process skip it and appends are refused until it is removed; if the process stops first, truncate the file to {start} bytes",
                        self.path.display()
                    );
                }
            }
            // The newline that ended a torn tail stays, and is acknowledged.
            if terminated_tail > 0 {
                let mut counts = match self.active_counts.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                counts.len += terminated_tail;
            }
            return false;
        }
        let offset = (!index_keys.is_empty() || !lifecycle_keys.is_empty()).then_some(start);
        self.writes_ok.fetch_add(1, Ordering::Relaxed);
        match self.chain_head.lock() {
            Ok(mut g) => *g = next_head,
            Err(poisoned) => *poisoned.into_inner() = next_head,
        }
        {
            let mut counts = match self.active_counts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            counts.len += terminated_tail + bytes.len() as u64;
            if let Some(approved) = verdict {
                counts.record(index_keys, approved);
            }
        }
        if let Some(offset) = offset {
            let mut index = match self.active_index.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            for key in index_keys {
                index.insert(key.clone(), offset);
            }
            drop(index);
            if !lifecycle_keys.is_empty() {
                let mut lifecycle = match self.lifecycle_index.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                for key in lifecycle_keys {
                    push_lifecycle_offset(&mut lifecycle, key.clone(), offset);
                }
            }
        }
        // Rotate AFTER a successful append, while still holding the lock, so
        // the size check and rename cannot interleave with another writer.
        self.rotate_if_needed(&mut file);
        true
    }
}

/// The verification record on the line at `offset` of `path`, if that line
/// is one.
fn read_record_at(path: &Path, offset: u64) -> Option<AuditRecord> {
    use std::io::Seek;
    let mut file = File::open(path).ok()?;
    file.seek(std::io::SeekFrom::Start(offset)).ok()?;
    let mut line = String::new();
    BufReader::new(file).read_line(&mut line).ok()?;
    serde_json::from_str::<AuditRecord>(line.trim_end()).ok()
}

/// Whether an archive index's entry for `key` agrees with the archive on
/// the checks that cost one seek: the record at `last_offset` is a
/// verification under `key` whose verdict the entry counts, and the entry
/// claims no more records than the archive has room for.
///
/// Round 29 (audit 2026-10-20, audit trail): an index is checked against
/// its archive by an unkeyed SHA-256, which proves the index was built
/// from these archive bytes by something that could compute a hash — not
/// that the counts in it are the ones the archive holds. Counts were the
/// one answer an index gave that was never read back. This does not make
/// the trail tamper-evident (whoever can write the data directory can
/// rewrite the archive and the index together); it catches an index whose
/// counts disagree with the archive it claims to describe.
fn index_entry_is_plausible(
    archive: &Path,
    index: &ArchiveIndex,
    entry: &archive_index::VerificationEntry,
    key: &VerificationKey<'_>,
) -> bool {
    let total = entry.approved.saturating_add(entry.refused);
    if total == 0
        || entry.last_offset >= index.archive_len
        || total > index.archive_len / MIN_VERIFICATION_LINE
    {
        return false;
    }
    match read_record_at(archive, entry.last_offset) {
        Some(r) if key.matches(&r) => {
            if r.approved {
                entry.approved > 0
            } else {
                entry.refused > 0
            }
        }
        _ => false,
    }
}

/// Whether a non-empty file's last byte is something other than a newline.
fn ends_without_newline(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return false;
    };
    if len == 0 || f.seek(SeekFrom::Start(len - 1)).is_err() {
        return false;
    }
    let mut last = [0u8; 1];
    f.read_exact(&mut last).is_ok() && last[0] != b'\n'
}

/// Every line of `file`, as bytes, skipping none (Round 19, F-19-23).
/// `lines().map_while(Result::ok)` ended the whole scan at the first line
/// that was not UTF-8 — one torn record hid every record after it in that
/// file. A line that cannot be read as text is skipped; the scan goes on.
fn for_each_line(file: impl std::io::Read, mut visit: impl FnMut(&str)) {
    let mut reader = BufReader::new(file);
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if let Ok(text) = std::str::from_utf8(&line) {
                    visit(text.trim_end_matches(['\n', '\r']));
                }
            }
        }
    }
}

/// Keep the first half and the last half of a bounded history (Round 19,
/// F-19-20 applied to the merged view).
fn bound_history<T>(mut rows: Vec<T>) -> Vec<T> {
    if rows.len() > MAX_LIFECYCLE_HISTORY {
        let head = MAX_LIFECYCLE_HISTORY / 2;
        let tail = MAX_LIFECYCLE_HISTORY - head;
        let cut = rows.len() - tail;
        rows.drain(head..cut);
    }
    rows
}

/// Default audit file name inside the data directory.
pub const AUDIT_FILENAME: &str = "audit.jsonl";

/// Build the audit file path from a data directory.
pub fn audit_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AUDIT_FILENAME)
}

/// RFC-3339 UTC timestamp for audit records, e.g.
/// `2026-08-06T16:35:03.123Z` (no external chrono dependency).
pub fn now_utc_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let (secs, millis) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs(), d.subsec_millis()))
        .unwrap_or((0, 0));
    // Days since Unix epoch → civil date (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mon <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mon, d, h, min, s, millis
    )
}

#[cfg(test)]
mod chain_trail_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str) -> AuditRecord {
        AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: "2026-09-05T00:00:00.000Z".to_string(),
            audit_trail_id: id.to_string(),
            content_hash: "hash".to_string(),
            transaction_sha256: None,
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "system-program".to_string(),
            manifest_version: None,
            approved: true,
            decision: None,
            executable: None,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "graphite-rotate-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn archives_in(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|n| n.starts_with("audit.jsonl."))
                    .unwrap_or(false)
            })
            .collect();
        v.sort();
        v
    }

    /// The active audit file must be bounded: an unbounded log means both disk
    /// exhaustion and an ever-growing full-file scan on every dashboard poll
    /// (2026-09-05 production audit).
    #[test]
    fn active_audit_file_is_bounded_by_rotation() {
        let dir = temp_dir("bounded");
        // Rotate aggressively so a handful of records crosses the threshold.
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        for i in 0..200 {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }
        let active = std::fs::metadata(audit_path(&dir)).unwrap().len();
        assert!(
            active < 4096,
            "active audit file must stay bounded by rotation, got {active} bytes"
        );
        assert!(
            !archives_in(&dir).is_empty(),
            "rotation must have produced at least one archive"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P9: rotation is not deletion. With the default retention (keep all),
    /// every record written must still exist somewhere on disk — the archive
    /// set plus the active file must account for all of them.
    #[test]
    fn rotation_preserves_every_record_by_default() {
        let dir = temp_dir("preserve");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        let total = 150;
        for i in 0..total {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }
        let mut seen = 0usize;
        let mut files = archives_in(&dir);
        files.push(audit_path(&dir));
        for f in files {
            let content = std::fs::read_to_string(&f).unwrap_or_default();
            seen += content.lines().filter(|l| !l.trim().is_empty()).count();
        }
        assert_eq!(
            seen, total,
            "default retention must preserve every audit record (P9)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rotation must produce a UNIQUE archive name every time, independently
    /// of how fast rotations happen.
    ///
    /// This is the regression test for a real CI failure. The archive name was
    /// `audit.jsonl.<unix-millis>` alone, so rotations sharing a millisecond
    /// produced the same name and `fs::rename` silently replaced the earlier
    /// archive — destroying its records. `rotation_preserves_every_record_by_default`
    /// below should have caught it, but whether it does depends entirely on
    /// filesystem speed: on a Windows dev machine each rotation took ~4ms
    /// (measured), so names never collided and the test passed, while Linux CI
    /// completed the same loop fast enough to collide and lost 126 of 150
    /// records.
    ///
    /// So this test drives the name generator DIRECTLY with a fixed stamp,
    /// removing the wall clock from the test entirely. Two rotations "in the
    /// same millisecond" is now a deterministic input rather than something we
    /// hope the scheduler produces.
    ///
    /// Verified to genuinely catch the bug: reverting to the millisecond-only
    /// name makes this fail on any platform. (An earlier version of this test
    /// drove real writes instead and passed even with the bug reverted, on
    /// Windows — false confidence, which is worse than no test.)
    #[test]
    fn archive_names_are_unique_within_a_single_millisecond() {
        let dir = temp_dir("same-ms");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();

        // The exact collision condition: one frozen timestamp, many rotations.
        const FROZEN_STAMP: u128 = 1_757_000_000_000;
        let names: Vec<PathBuf> = (0..500)
            .map(|_| log.next_archive_path(FROZEN_STAMP).unwrap())
            .collect();

        let unique: std::collections::BTreeSet<&PathBuf> = names.iter().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "{} of {} archive names collided within one millisecond — fs::rename replaces an \
             existing destination, so each collision silently destroys an archive and every \
             record in it",
            names.len() - unique.len(),
            names.len()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Names generated within one millisecond must ALSO sort chronologically,
    /// since `prune_archives` picks the oldest lexically. Zero-padding is what
    /// makes that true; without it `-10` sorts before `-2`.
    #[test]
    fn archive_names_within_a_millisecond_sort_in_creation_order() {
        let dir = temp_dir("same-ms-order");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();
        const FROZEN_STAMP: u128 = 1_757_000_000_000;

        let created: Vec<PathBuf> = (0..25)
            .map(|_| log.next_archive_path(FROZEN_STAMP).unwrap())
            .collect();
        let mut sorted = created.clone();
        sorted.sort();

        assert_eq!(
            created, sorted,
            "lexical order must match creation order, or pruning deletes newer audit history \
             while keeping older"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// End-to-end: records must survive rapid back-to-back rotation. This one
    /// IS timing-dependent (it only collides on a fast filesystem), which is
    /// exactly why the two deterministic tests above exist — but it is kept
    /// because it exercises the real write path rather than the name generator
    /// in isolation.
    #[test]
    fn every_record_survives_rapid_back_to_back_rotation() {
        let dir = temp_dir("rapid");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();
        let writes = 60;
        for i in 0..writes {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }

        let mut files = archives_in(&dir);
        files.push(audit_path(&dir));
        let mut seen = 0usize;
        for f in files {
            let content = std::fs::read_to_string(&f).unwrap_or_default();
            seen += content.lines().filter(|l| !l.trim().is_empty()).count();
        }
        assert_eq!(
            seen, writes,
            "every record must survive rapid rotation (P9 — rotation is not deletion)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Archive names must sort chronologically, because `prune_archives`
    /// decides what is "oldest" by lexical order. An unpadded counter would
    /// order `-10` before `-2` and prune the wrong file — deleting newer audit
    /// history while keeping older.
    #[test]
    fn archive_names_sort_chronologically() {
        let dir = temp_dir("sort-order");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();
        for i in 0..15 {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }
        let archives = archives_in(&dir); // archives_in() sorts lexically
        let mut by_mtime = archives.clone();
        by_mtime.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        assert_eq!(
            archives, by_mtime,
            "lexical archive order must match creation order, or pruning removes the wrong files"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pruning is opt-in and, when enabled, actually bounds the archive count.
    #[test]
    fn explicit_retention_prunes_oldest_archives_only() {
        let dir = temp_dir("prune");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 2).unwrap();
        for i in 0..300 {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }
        let archives = archives_in(&dir);
        assert!(
            archives.len() <= 2,
            "explicit retention must bound archive count, got {}",
            archives.len()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rotation disabled must behave exactly as before (no archives at all) —
    /// operators who need a single append-only file keep it.
    #[test]
    fn rotation_can_be_disabled() {
        let dir = temp_dir("disabled");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        for i in 0..200 {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }
        assert!(
            archives_in(&dir).is_empty(),
            "rotate_bytes=0 must never rotate"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A stopped audit trail was previously invisible. Successful writes must
    /// be counted so /health and /metrics can expose durability state.
    #[test]
    fn audit_health_counts_successful_writes() {
        let dir = temp_dir("health");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        assert_eq!(log.health().writes_ok, 0);
        for i in 0..5 {
            assert!(log.append(&rec(&format!("id-{i}"))));
        }
        let h = log.health();
        assert_eq!(h.writes_ok, 5);
        assert_eq!(h.writes_failed, 0);
        assert!(
            h.active_bytes > 0,
            "active_bytes must reflect the real file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// GAP-2026-08-06-3: the audit record must carry the REAL L3/L8 layer
    /// states (never the old phantom `passed: true`).
    #[test]
    fn audit_record_serializes_l3_and_l8_status() {
        let record = AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: "2026-08-06T00:00:00.000Z".to_string(),
            audit_trail_id: "gr-test".to_string(),
            content_hash: "abc".to_string(),
            transaction_sha256: None,
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "system-program".to_string(),
            manifest_version: None,
            approved: true,
            decision: None,
            executable: None,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        };
        let json = serde_json::to_string(&record).expect("audit record serializes");
        assert!(
            json.contains("\"l3_status\":\"inconclusive\""),
            "audit record must carry the L3 state, got: {}",
            json
        );
        assert!(
            json.contains("\"l8_status\":\"inconclusive\""),
            "audit record must carry the L8 state, got: {}",
            json
        );
    }

    /// Bounded read: the tail cap keeps memory bounded as the log grows,
    /// totals still report true volume, and a torn final line never fails
    /// the read (append-only crash tail).
    #[test]
    fn read_tail_filtered_caps_memory_and_reports_totals() {
        let dir = std::env::temp_dir().join(format!(
            "gr-audit-tail-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        {
            let log = AuditLog::open(&path).unwrap();
            for i in 0..10 {
                assert!(log.append(&AuditRecord {
                    event_type: LifecycleEvent::Verification,
                    timestamp: format!("t{i}"),
                    audit_trail_id: format!("id{i}"),
                    content_hash: "h".into(),
                    transaction_sha256: None,
                    program_id: if i % 2 == 0 {
                        "AAA".into()
                    } else {
                        "BBB".into()
                    },
                    instruction_name: "transfer".into(),
                    protocol_name: "system".into(),
                    manifest_version: None,
                    approved: i % 2 == 0,
                    decision: None,
                    executable: None,
                    confidence: 0.5,
                    risk_status: "Clear".into(),
                    policy_verdict: if i % 2 == 0 {
                        "Approved".into()
                    } else {
                        "Blocked".into()
                    },
                    l3_status: "inconclusive".into(),
                    l8_status: "inconclusive".into(),
                    wallet_profile: None,
                }));
            }
        }
        // Append a torn final line (simulating a crash mid-write).
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "{{\"timestamp\": \"truncated\"").unwrap();
        drop(f);

        let log = AuditLog::open(&path).unwrap();
        let (records, errors, total, _) = log.read_tail_filtered(4, AuditSelector::Approved);
        // 10 records, 5 approved; keep filter -> 5 approved, cap 4 -> last 4.
        assert_eq!(total, 5, "total must count all approved records");
        assert_eq!(records.len(), 4, "tail cap must bound the retained set");
        // Raw read is chronological (append order); the API layer reverses.
        // The 4 most recent approved by file position are i = 2, 4, 6, 8.
        let ids: Vec<&str> = records.iter().map(|r| r.audit_trail_id.as_str()).collect();
        assert_eq!(ids, vec!["id2", "id4", "id6", "id8"]);
        assert!(errors.is_empty(), "no error records written");

        // tail == 0 retains nothing but still reports exact totals.
        let (empty, _, zero_total, _) = log.read_tail_filtered(0, AuditSelector::All);
        assert!(empty.is_empty(), "tail 0 must retain nothing");
        assert_eq!(zero_total, 10, "totals stay exact under tail 0");

        // Error records are capped at tail too, and count toward total_errors.
        for i in 0..4 {
            assert!(log.append_error(&AuditErrorRecord {
                timestamp: format!("te{i}"),
                program_id: format!("prg{i}"),
                instruction_name: "transfer".into(),
                error: "bad payload".into(),
                error_type: "bad_input".into(),
                status: 400,
            }));
        }
        let (_, errs, _, err_total) = log.read_tail_filtered(2, AuditSelector::All);
        assert_eq!(err_total, 4, "all error records counted");
        assert_eq!(errs.len(), 2, "error ring capped at tail");
        // Most recent two by file position: prg2, prg3 (chronological).
        let eids: Vec<&str> = errs.iter().map(|e| e.program_id.as_str()).collect();
        assert_eq!(eids, vec!["prg2", "prg3"]);

        // Observations streaming: 10 records, 5 per program, torn line ignored.
        let counts = log.observations_by_program();
        assert_eq!(counts.get("AAA"), Some(&5));
        assert_eq!(counts.get("BBB"), Some(&5));
        assert_eq!(counts.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A record with a chosen id, hash, program and verdict.
    fn rec_with(id: &str, hash: &str, program: &str, approved: bool) -> AuditRecord {
        let mut r = rec(id);
        r.content_hash = hash.to_string();
        r.program_id = program.to_string();
        r.approved = approved;
        r.policy_verdict = if approved { "Approved" } else { "Blocked" }.to_string();
        r
    }

    /// Lines in the active file only — what the read path used to see.
    fn active_only_count(dir: &Path) -> usize {
        std::fs::read_to_string(audit_path(dir))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    }

    /// The read path must account for the whole trail, not the active file.
    ///
    /// Before 2026-09-12 `read_tail_filtered` and `observations_by_program`
    /// opened only `audit.jsonl`. After a rotation the dashboard's totals fell
    /// to whatever had been written since, `/api/protocols/top` forgot every
    /// program not seen since, and — the part that matters — L8 reconciliation
    /// could no longer find a verdict that had rotated out, so a BLOCKED
    /// transaction submitted anyway reconciled as `NoVerificationOnRecord`
    /// instead of `BlockedButExecuted`.
    ///
    /// Anti-vacuity: the test first proves the active file alone holds fewer
    /// records than were written, so agreement with the total is agreement
    /// with the archives, not with the active file.
    #[test]
    fn read_path_covers_every_archive_after_rotation() {
        let dir = temp_dir("read-archives");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        let total = 120usize;
        let mut blocked = 0usize;
        for i in 0..total {
            let approved = i % 3 != 0;
            if !approved {
                blocked += 1;
            }
            let program = if i % 2 == 0 { "ProgA" } else { "ProgB" };
            assert!(log.append(&rec_with(
                &format!("id-{i}"),
                &format!("hash-{i}"),
                program,
                approved
            )));
        }
        assert!(
            archives_in(&dir).len() >= 3,
            "the test needs several archives to be meaningful"
        );
        let active = active_only_count(&dir);
        assert!(
            active < total,
            "the active file must hold fewer than all records ({active} of {total}) or this test proves nothing"
        );

        // Totals over the whole trail.
        let (records, errors, n_all, n_err) = log.read_tail_filtered(10, AuditSelector::All);
        assert_eq!(
            n_all, total,
            "total must count every archive, not the active file"
        );
        assert_eq!(n_err, 0);
        assert!(errors.is_empty());
        // The newest ten, oldest-first, crossing the file boundary if needed.
        let ids: Vec<String> = records.iter().map(|r| r.audit_trail_id.clone()).collect();
        let want: Vec<String> = (total - 10..total).map(|i| format!("id-{i}")).collect();
        assert_eq!(ids, want, "the tail must be the newest records in order");

        let (blocked_records, _, n_blocked, _) =
            log.read_tail_filtered(1000, AuditSelector::Blocked);
        assert_eq!(n_blocked, blocked);
        assert_eq!(
            blocked_records.len(),
            blocked,
            "a large tail returns every blocked record"
        );
        assert!(blocked_records.iter().all(|r| !r.approved));
        // And in order, across every file boundary.
        let ids: Vec<String> = blocked_records
            .iter()
            .map(|r| r.audit_trail_id.clone())
            .collect();
        let want: Vec<String> = (0..total)
            .filter(|i| i % 3 == 0)
            .map(|i| format!("id-{i}"))
            .collect();
        assert_eq!(ids, want);

        // Per-program counts sum across archives.
        let counts = log.observations_by_program();
        assert_eq!(counts.get("ProgA").copied(), Some(total / 2));
        assert_eq!(counts.get("ProgB").copied(), Some(total / 2));

        // L8's join finds a verdict that lives in the OLDEST archive.
        let found = log
            .last_verification_for("hash-0")
            .expect("the first record rotated into the oldest archive and must still be found");
        assert_eq!(found.audit_trail_id, "id-0");
        assert!(!found.approved, "id-0 was blocked (0 % 3 == 0)");
        assert!(log.last_verification_for("hash-never").is_none());
        assert!(log.last_verification_for("   ").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// When the same content hash was verified more than once, the record
    /// that governed is the LAST one — even when the earlier verdict is in a
    /// newer-looking position of an older file.
    #[test]
    fn last_verification_is_the_newest_across_files() {
        let dir = temp_dir("last-across");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        // Blocked first, then padding to force rotation, then approved.
        assert!(log.append(&rec_with("first", "same-hash", "P", false)));
        for i in 0..40 {
            assert!(log.append(&rec_with(&format!("pad-{i}"), "other", "P", true)));
        }
        assert!(log.append(&rec_with("second", "same-hash", "P", true)));
        for i in 0..40 {
            assert!(log.append(&rec_with(&format!("pad2-{i}"), "other", "P", true)));
        }
        assert!(archives_in(&dir).len() >= 2);
        let governed = log.last_verification_for("same-hash").unwrap();
        assert_eq!(governed.audit_trail_id, "second");
        assert!(governed.approved);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Archive statistics are computed once and forgotten when pruned.
    ///
    /// The cache is what keeps the read path's cost bounded by the active
    /// file rather than the whole history; a cache that never populated
    /// would silently reintroduce the full-history scan on every poll, and
    /// one that kept pruned archives would report records that no longer
    /// exist.
    #[test]
    fn archive_statistics_are_cached_and_track_pruning() {
        let dir = temp_dir("cache");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        for i in 0..60 {
            assert!(log.append(&rec_with(&format!("id-{i}"), "h", "P", i % 2 == 0)));
        }
        let archives = archives_in(&dir);
        assert!(archives.len() >= 2);
        assert!(
            log.archive_stats.lock().unwrap().is_empty(),
            "nothing read yet"
        );

        let (_, _, n1, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(n1, 60);
        let cached = log.archive_stats.lock().unwrap().len();
        assert_eq!(
            cached,
            archives.len(),
            "every archive's statistics are cached after one read"
        );

        // The cache is consulted: corrupt one record in the oldest archive
        // WITHOUT changing the file length. A rescan would now skip that line
        // as malformed and report 59; the cache still says 60.
        let oldest = archives[0].clone();
        let original = std::fs::read_to_string(&oldest).unwrap();
        let same_length = original.replacen("\"approved\":true", "\"approved\":truX", 1);
        assert_eq!(original.len(), same_length.len());
        assert_ne!(original, same_length);
        std::fs::write(&oldest, &same_length).unwrap();
        let (_, _, n2, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(n2, 60, "an unchanged length is served from the cache");

        // A length change invalidates: the corrupted line is now seen.
        std::fs::write(
            &oldest,
            format!(
                "{same_length}
"
            ),
        )
        .unwrap();
        let (_, _, n3, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(n3, 59, "a length mismatch re-scans the archive");
        assert_eq!(
            log.archive_stats
                .lock()
                .unwrap()
                .get(&oldest)
                .map(|s| s.len),
            Some(std::fs::metadata(&oldest).unwrap().len()),
            "the rescan re-caches under the new length"
        );

        // Pruning drops the entry. One writer at a time (Round 30): the
        // first log, and every background job holding it, goes first.
        log.wait_for_index_jobs();
        drop(log);
        let pruning = AuditLog::open_with_rotation(audit_path(&dir), 512, 1).unwrap();
        let _ = pruning.read_tail_filtered(1, AuditSelector::All);
        for i in 0..60 {
            assert!(pruning.append(&rec_with(&format!("late-{i}"), "h", "P", true)));
        }
        let remaining = archives_in(&dir);
        assert_eq!(remaining.len(), 1, "max_archives == 1 keeps one archive");
        let _ = pruning.read_tail_filtered(1, AuditSelector::All);
        let cache = pruning.archive_stats.lock().unwrap();
        assert!(
            cache.keys().all(|k| remaining.contains(k)),
            "cache must not hold pruned archives: {:?}",
            cache.keys().collect::<Vec<_>>()
        );
        drop(cache);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Readers polling while the writer rotates never see a torn trail, and
    /// the final accounting is exact.
    ///
    /// The snapshot (archive list + active handle) is taken under the append
    /// lock so a rotation cannot land between the two. Without that a read
    /// could miss the just-rotated archive (listed before the rename, opened
    /// after) or count it twice.
    #[test]
    fn concurrent_reads_during_rotation_never_over_or_under_count() {
        let dir = temp_dir("concurrent");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1024, 0).unwrap();
        let total = 400usize;
        let writer = {
            let log = log.clone();
            std::thread::spawn(move || {
                for i in 0..total {
                    assert!(log.append(&rec_with(&format!("id-{i}"), "h", "P", true)));
                }
            })
        };
        let reader = {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut last = 0usize;
                for _ in 0..200 {
                    let (records, _, n, _) = log.read_tail_filtered(5, AuditSelector::All);
                    // Monotone: the trail only grows.
                    assert!(n >= last, "total went backwards: {last} -> {n}");
                    assert!(n <= total);
                    last = n;
                    // Whatever tail we got is in order and contiguous.
                    let ids: Vec<usize> = records
                        .iter()
                        .map(|r| r.audit_trail_id[3..].parse().unwrap())
                        .collect();
                    for w in ids.windows(2) {
                        assert_eq!(w[1], w[0] + 1, "tail must be contiguous: {ids:?}");
                    }
                    std::thread::yield_now();
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
        let (_, _, n, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(n, total);
        assert!(log.health().rotations_ok > 0);
        assert_eq!(log.health().rotations_failed, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rotation that cannot happen is counted, and the record that
    /// triggered it is still appended.
    ///
    /// On Windows the realistic cause is a foreign handle without
    /// `FILE_SHARE_DELETE` — a log shipper, an antivirus scanner,
    /// `Get-Content -Wait`. Rust's own handles carry that share mode, which
    /// is why the log's own append handle never blocks its own rotation; this
    /// test opens the file the way a foreign program would.
    #[cfg(windows)]
    #[test]
    fn rotation_failure_is_counted_and_never_drops_a_record() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        let dir = temp_dir("foreign-handle");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        let foreign = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE) // no FILE_SHARE_DELETE
            .open(audit_path(&dir))
            .unwrap();
        for i in 0..40 {
            assert!(
                log.append(&rec_with(&format!("held-{i}"), "h", "P", true)),
                "the record must be appended even though rotation is blocked"
            );
        }
        let h = log.health();
        assert!(h.rotations_failed > 0, "a blocked rotation must be counted");
        assert_eq!(h.rotations_ok, 0);
        assert!(archives_in(&dir).is_empty());
        assert_eq!(active_only_count(&dir), 40, "nothing was dropped");
        assert!(h.active_bytes > 512, "the active file kept growing");

        // Release the foreign handle: the very next append rotates.
        drop(foreign);
        assert!(log.append(&rec_with("after", "h", "P", true)));
        assert!(
            log.health().rotations_ok >= 1,
            "rotation resumes once the handle is gone"
        );
        assert!(!archives_in(&dir).is_empty());
        let (_, _, n, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(
            n, 41,
            "every record is still accounted for across the rotation"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The Unix twin. Round 30 (K-12): it used a read-only directory and
    /// returned early when run as root — which is how this machine and CI's
    /// containers run it, so it passed without exercising anything. The
    /// rename now fails through the fault seam, which applies to every user;
    /// the read-only directory is still tried first where it means
    /// something (not root).
    #[cfg(unix)]
    #[test]
    fn rotation_failure_is_counted_and_never_drops_a_record() {
        let dir = temp_dir("rotation-rename-fails");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        log.faults.store(FAULT_ROTATE_RENAME, Ordering::SeqCst);
        for i in 0..40 {
            assert!(
                log.append(&rec_with(&format!("held-{i}"), "h", "P", true)),
                "the record must be appended even though rotation is blocked"
            );
        }
        let h = log.health();
        assert!(h.rotations_failed > 0, "a blocked rotation must be counted");
        assert_eq!(h.rotations_ok, 0);
        assert!(archives_in(&dir).is_empty());
        assert_eq!(active_only_count(&dir), 40, "nothing was dropped");
        assert!(h.active_bytes > 512, "the active file kept growing");
        log.faults.store(0, Ordering::SeqCst);
        assert!(log.append(&rec_with("after", "h", "P", true)));
        assert!(log.health().rotations_ok >= 1);
        assert!(!archives_in(&dir).is_empty());
        let (_, _, n, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(n, 41);
        // The chain runs unbroken through the failed rotations.
        let report = log.verify(&[], None).unwrap();
        assert!(report.intact(), "{report:?}");
        assert_eq!(report.chained_records, 41);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same through a real filesystem refusal, where one applies: a
    /// directory the process cannot rename inside (not as root, which
    /// ignores directory permissions).
    #[cfg(unix)]
    #[test]
    fn rotation_in_a_read_only_directory_is_counted_and_never_drops_a_record() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("readonly-dir");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Whether this process is subject to directory permissions, probed
        // rather than assumed.
        let probe = dir.join("probe");
        if std::fs::write(&probe, b"x").is_ok() {
            std::fs::remove_file(&probe).ok();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!(
                "read-only directory not enforced for this user; the failure path is covered by rotation_failure_is_counted_and_never_drops_a_record"
            );
            return;
        }
        for i in 0..40 {
            assert!(log.append(&rec_with(&format!("held-{i}"), "h", "P", true)));
        }
        let h = log.health();
        assert!(h.rotations_failed > 0, "a blocked rotation must be counted");
        assert_eq!(h.rotations_ok, 0);
        assert_eq!(active_only_count(&dir), 40, "nothing was dropped");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(log.append(&rec_with("after", "h", "P", true)));
        assert!(log.health().rotations_ok >= 1);
        let (_, _, n, _) = log.read_tail_filtered(1, AuditSelector::All);
        assert_eq!(n, 41);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Round 9: a lifecycle event's fields are bounded on the way to disk.
    /// Before, the record was written verbatim, so a 1 MiB `detail` was a
    /// 1 MiB line.
    #[test]
    fn lifecycle_event_fields_are_bounded_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "gr-lifecycle-bound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        let big = "x".repeat(1024 * 1024);
        assert!(log.append_lifecycle(&LifecycleEventRecord {
            event_type: LifecycleEvent::Signing,
            timestamp: now_utc_rfc3339(),
            content_hash: big.clone(),
            verdict_on_record: Some(VerdictOnRecord::NotFound),
            verdict_on_record_key: Some(VerificationKeyKind::ContentHash),
            transaction_sha256: Some(big.clone()),
            audit_trail_id: Some(big.clone()),
            transaction_signature: Some(big.clone()),
            reported_by: Some(big.clone()),
            detail: Some(big.clone()),
            observed_by_graphite: false,
            sequence_anomalies: vec![big.clone()],
        }));
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert!(
            on_disk < 5 * 1024,
            "five 1 MiB fields must land as five bounded ones: {on_disk} bytes on disk"
        );
        let line = std::fs::read_to_string(&path).unwrap();
        assert!(line.contains("[truncated, 1048576 chars total]"), "{line}");
        assert!(
            line.contains("\"verdict_on_record\":\"not_found\""),
            "{line}"
        );

        // Round 11: a detail within the boundary's bound lands whole. The
        // server's own L8 detail runs past 256 characters when it carries a
        // rejected-bytes reason, and the marker an investigator greps for
        // sits at the end of it.
        let long_detail = format!(
            "L8 reconciliation: Unavailable {{ reason: \"{}\" }}; attribution: None; chain bytes rejected: yes",
            "r".repeat(600)
        );
        assert!(long_detail.chars().count() <= MAX_LIFECYCLE_DETAIL_CHARS);
        assert!(log.append_lifecycle(&LifecycleEventRecord {
            event_type: LifecycleEvent::Confirmation,
            timestamp: now_utc_rfc3339(),
            content_hash: "0123456789abcdef".to_string(),
            verdict_on_record: None,
            verdict_on_record_key: None,
            transaction_sha256: None,
            audit_trail_id: None,
            transaction_signature: None,
            reported_by: None,
            detail: Some(long_detail.clone()),
            observed_by_graphite: true,
            sequence_anomalies: Vec::new(),
        }));
        let text = std::fs::read_to_string(&path).unwrap();
        let last = text.lines().last().unwrap();
        let row: serde_json::Value = serde_json::from_str(last).unwrap();
        assert_eq!(row["detail"].as_str(), Some(long_detail.as_str()));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Round 9: what an L8 / lifecycle lookup costs against a full active
    /// file. Measurement, reported. What is asserted is structural: a hit, a
    /// miss (a hash with no verification on record — the case a caller can
    /// force at will) and a verdict count all answer from the index without
    /// reading the file (`active_lookup_scans`, `active_count_scans`), plus a
    /// one-second sanity bound.
    ///
    /// Until 2026-09-29 the assertion was a 50 ms wall-clock bound, right
    /// after writing 64 MB: it failed under load on the development machine
    /// (a 58.5 ms hit, a 107 ms miss) with nothing scanned, and a fast enough
    /// scan would have passed it. The witness is what says whether the file
    /// was read.
    #[test]
    fn last_verification_scans_a_full_active_file() {
        let dir = std::env::temp_dir().join(format!(
            "gr-l8-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        // Written directly, without per-record sync, to build the file fast.
        {
            let mut f = std::fs::File::create(&path).unwrap();
            let mut w = std::io::BufWriter::new(&mut f);
            let mut i = 0u64;
            let mut written = 0u64;
            while written < 64 * 1024 * 1024 {
                let r = rec_with(
                    &format!("gr-{i}"),
                    &format!("{i:016x}"),
                    "11111111111111111111111111111111",
                    i.is_multiple_of(2),
                );
                let line = serde_json::to_string(&r).unwrap();
                written += line.len() as u64 + 1;
                writeln!(w, "{line}").unwrap();
                i += 1;
            }
            w.flush().unwrap();
        }
        let len = std::fs::metadata(&path).unwrap().len();
        // What the lookup cost before the index: parse every line.
        let started = std::time::Instant::now();
        let mut found = None;
        for line in BufReader::new(File::open(&path).unwrap())
            .lines()
            .map_while(Result::ok)
        {
            if let Ok(r) = serde_json::from_str::<AuditRecord>(&line) {
                if r.content_hash == "ffffffffffffffff" {
                    found = Some(r);
                }
            }
        }
        let full_scan = started.elapsed();
        assert!(found.is_none());

        let started = std::time::Instant::now();
        let log = AuditLog::open(&path).unwrap();
        let open_cost = started.elapsed();
        let started = std::time::Instant::now();
        let hit = log.last_verification_for("0000000000000010");
        let hit_cost = started.elapsed();
        assert_eq!(hit.map(|r| r.audit_trail_id), Some("gr-16".to_string()));
        let started = std::time::Instant::now();
        let miss = log.last_verification_for("ffffffffffffffff");
        let miss_cost = started.elapsed();
        assert!(miss.is_none());
        // Round 22: the verdict count L8 takes beside the lookup is indexed
        // too — over this 64 MB file it reads nothing.
        let started = std::time::Instant::now();
        assert_eq!(
            log.count_verifications(VerificationKey::ContentHash("0000000000000010")),
            (1, 0)
        );
        assert_eq!(
            log.count_verifications(VerificationKey::ContentHash("ffffffffffffffff")),
            (0, 0)
        );
        let count_cost = started.elapsed();
        assert_eq!(
            log.active_count_scans.load(Ordering::Relaxed),
            0,
            "an indexed count must not scan the file"
        );
        // A record appended after open is found through the index too, and
        // the newest one wins.
        assert!(log.append(&rec_with("gr-new", "0000000000000010", "P", false)));
        let newest = log.last_verification_for("0000000000000010").unwrap();
        assert_eq!(newest.audit_trail_id, "gr-new");
        assert!(!newest.approved);
        println!(
            "round9: last_verification_for over a {} MB active file: full scan {:?}; indexed: open {:?}, hit {:?}, miss {:?}; two verdict counts {:?}",
            len / (1024 * 1024),
            full_scan,
            open_cost,
            hit_cost,
            miss_cost,
            count_cost
        );
        assert_eq!(
            log.active_lookup_scans.load(Ordering::Relaxed),
            0,
            "an indexed lookup must not scan the file"
        );
        // No wall-clock bound (2026-09-29 audit, A6-11): the scan counters
        // above are the witness that the lookups were indexed, and the timings
        // are printed for the record.
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A stale or wrong index entry never yields a wrong answer, and a
    /// non-UTF-8 line in the active file does not end the index build.
    #[test]
    fn last_verification_index_never_answers_from_a_broken_entry() {
        let dir = std::env::temp_dir().join(format!(
            "gr-l8-index-broken-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = audit_path(&dir);
        // A record, then a line of invalid UTF-8, then another record.
        {
            let mut f = std::fs::File::create(&path).unwrap();
            let a =
                serde_json::to_string(&rec_with("gr-a", "aaaaaaaaaaaaaaaa", "P", true)).unwrap();
            let b =
                serde_json::to_string(&rec_with("gr-b", "bbbbbbbbbbbbbbbb", "P", false)).unwrap();
            f.write_all(a.as_bytes()).unwrap();
            f.write_all(b"\n\xff\xfe garbage \xc3\n").unwrap();
            f.write_all(b.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(
            log.last_verification_for("bbbbbbbbbbbbbbbb")
                .map(|r| r.audit_trail_id),
            Some("gr-b".to_string()),
            "the record after the bad line must be indexed"
        );
        assert_eq!(log.active_lookup_scans.load(Ordering::Relaxed), 0);
        // Poison the index: point the hash at a wrong offset. The lookup
        // must fall back to a scan and still find the right record.
        //
        // The entry is the index's own key (`ch:<hash>`). Until 2026-09-29
        // this inserted the bare hash — a key the index has not used since
        // Round 10's prefixes — so the lookup never met the poisoned entry,
        // the fallback never ran, and the test passed without testing it.
        // The scan counter below is what showed it.
        let poisoned = VerificationKey::ContentHash("aaaaaaaaaaaaaaaa").index_key();
        assert!(log.active_index.lock().unwrap().contains_key(&poisoned));
        log.active_index.lock().unwrap().insert(poisoned, 7);
        let r = log.last_verification_for("aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(r.audit_trail_id, "gr-a");
        assert!(r.approved);
        assert_eq!(
            log.active_lookup_scans.load(Ordering::Relaxed),
            1,
            "the poisoned entry must have been refused and the file scanned"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The index survives what the file goes through: a rotation empties it
    /// (the offsets point into the archive now, and the archive scan finds
    /// the record), and a reopen rebuilds it from disk.
    #[test]
    fn last_verification_index_tracks_rotation_and_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "gr-l8-index-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = audit_path(&dir);
        let log = AuditLog::open_with_rotation(&path, 2_000, 0).unwrap();
        for i in 0..20 {
            assert!(log.append(&rec_with(
                &format!("gr-{i}"),
                &format!("{i:016x}"),
                "P",
                true
            )));
        }
        assert!(
            log.health().rotations_ok >= 1,
            "rotation must have happened"
        );
        // Old records are in archives; the newest is in the active file.
        for i in 0..20 {
            let r = log
                .last_verification_for(&format!("{i:016x}"))
                .unwrap_or_else(|| panic!("record {i} lost across rotation"));
            assert_eq!(r.audit_trail_id, format!("gr-{i}"));
        }
        // Round 30: the writer holds the trail's lock until its last clone
        // (a background index job's) is gone.
        log.wait_for_index_jobs();
        drop(log);
        let reopened = AuditLog::open_with_rotation(&path, 2_000, 0).unwrap();
        for i in 0..20 {
            assert!(reopened
                .last_verification_for(&format!("{i:016x}"))
                .is_some());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    fn counts_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gr-l8-counts-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const COUNTED_TX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn counted(id: &str, approved: bool) -> AuditRecord {
        let mut r = rec_with(id, "00000000000000aa", "P", approved);
        r.transaction_sha256 = Some(COUNTED_TX.to_string());
        r
    }

    fn count_scans(log: &AuditLog) -> u64 {
        log.active_count_scans.load(Ordering::Relaxed)
    }

    /// Round 22: `count_verifications` — run by every L8 reconciliation
    /// with a chain digest — answers for the active file from its counts,
    /// without reading the file, and the counts are right after open, after
    /// appends of every kind of row, and across rotation and reopen.
    ///
    /// The structural witness is `active_count_scans`: the active file is
    /// read by a count only when the counts do not account for it. Before
    /// Round 22 every count was a pass over the whole active file.
    #[test]
    fn verdict_counts_are_indexed_across_open_append_and_rotation() {
        let dir = counts_dir("indexed");
        let path = audit_path(&dir);
        let key = VerificationKey::TransactionSha256(COUNTED_TX);
        {
            let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
            assert_eq!(log.count_verifications(key), (0, 0));
            for (i, approved) in [true, false, true].into_iter().enumerate() {
                assert!(log.append(&counted(&format!("gr-{i}"), approved)));
            }
            // Rows that are not verifications of this transaction: another
            // verification, an error record and a lifecycle row. Each moves
            // the file on; none may move this count.
            assert!(log.append(&rec_with("gr-other", "00000000000000bb", "P", false)));
            assert!(log.append_error(&AuditErrorRecord {
                timestamp: "t".into(),
                program_id: "P".into(),
                instruction_name: "transfer".into(),
                error: "bad payload".into(),
                error_type: "bad_input".into(),
                status: 400,
            }));
            assert!(log.append_lifecycle(&lifecycle(LifecycleEvent::Signing, "gr-0", None)));
            assert_eq!(log.count_verifications(key), (2, 1));
            assert_eq!(
                log.count_verifications(VerificationKey::AuditTrailId("gr-1")),
                (0, 1)
            );
            assert_eq!(
                log.count_verifications(VerificationKey::ContentHash("00000000000000aa")),
                (2, 1)
            );
            assert_eq!(
                log.count_verifications(VerificationKey::ContentHash("00000000000000bb")),
                (0, 1)
            );
            assert_eq!(
                count_scans(&log),
                0,
                "an indexed count must not read the file"
            );
        }
        // Reopen: open's one pass rebuilds the counts.
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert_eq!(log.count_verifications(key), (2, 1));
        assert!(log.append(&counted("gr-3", false)));
        assert_eq!(log.count_verifications(key), (2, 2));
        assert_eq!(count_scans(&log), 0);
        drop(log);
        // Rotation after the next append: every record moves to an archive,
        // the counts are reset with the fresh file, and the total is neither
        // lost nor counted twice.
        let log = AuditLog::open_with_rotation(&path, 1, 0).unwrap();
        assert!(log.append(&counted("gr-4", true)));
        assert!(
            log.health().rotations_ok >= 1,
            "rotation must have happened"
        );
        assert_eq!(log.count_verifications(key), (3, 2));
        assert!(log.active_counts.lock().unwrap().by_key.is_empty());
        assert_eq!(
            count_scans(&log),
            0,
            "rotation must leave counts the file agrees with"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Counts the active file contradicts are never answered from: a record
    /// that reached the file some other way — here written straight to it,
    /// as a write that failed part-way would leave bytes behind — makes the
    /// next count read the file, replace the counts with what it holds, and
    /// go back to answering from them.
    #[test]
    fn a_verdict_count_the_active_file_contradicts_is_recounted() {
        let dir = counts_dir("recount");
        let path = audit_path(&dir);
        let key = VerificationKey::TransactionSha256(COUNTED_TX);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert!(log.append(&counted("gr-0", true)));
        assert_eq!(log.count_verifications(key), (1, 0));
        assert_eq!(count_scans(&log), 0);
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            let line = serde_json::to_string(&counted("gr-foreign", false)).unwrap();
            writeln!(f, "{line}").unwrap();
        }
        assert_eq!(
            log.count_verifications(key),
            (1, 1),
            "the record the counts did not see must be counted"
        );
        assert_eq!(
            count_scans(&log),
            1,
            "the contradiction is resolved from the file"
        );
        assert_eq!(log.count_verifications(key), (1, 1));
        assert!(log.append(&counted("gr-1", true)));
        assert_eq!(log.count_verifications(key), (2, 1));
        assert_eq!(count_scans(&log), 1, "recounted once, indexed again after");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A file that ends in a partial line gets a newline before the next
    /// record (Round 19, F-19-23). That byte is part of what the counts
    /// account for, or every count after it would read the file.
    #[test]
    fn verdict_counts_account_for_a_terminated_torn_tail() {
        let dir = counts_dir("torn");
        let path = audit_path(&dir);
        std::fs::write(&path, b"{\"audit_trail_id\":\"gr-torn").unwrap();
        let key = VerificationKey::TransactionSha256(COUNTED_TX);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert!(log.append(&counted("gr-0", false)));
        assert_eq!(log.count_verifications(key), (0, 1));
        assert_eq!(count_scans(&log), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Measures what per-record device sync costs on this machine — and
    /// deliberately asserts nothing about it.
    ///
    /// `append` calls `sync_data` (a real device flush) instead of the no-op
    /// `File::flush`. Nothing observable from userspace distinguishes the
    /// two until the machine loses power, and timing cannot stand in for
    /// that: a first version of this test asserted "at least 2 µs per
    /// append" and still passed with `flush` restored, because a plain write
    /// syscall already costs more than that — a vacuous assertion, worse
    /// than none. On tmpfs or a fast NVMe `sync_data` can be microseconds
    /// too, so no threshold is honest across machines.
    ///
    /// So this prints three numbers — the cost of an append, of a bare
    /// `sync_data`, and of a bare `flush` on the same file — for the report
    /// to carry as observed values. The guarantee itself is established by
    /// reading `append_line`, and by the reviewer who checks that its
    /// `and_then` still names `sync_data`.
    #[test]
    fn audit_append_syncs_the_device() {
        let dir = temp_dir("sync-cost");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let n = 200u32;
        let started = std::time::Instant::now();
        for i in 0..n {
            assert!(log.append(&rec_with(&format!("s-{i}"), "h", "P", true)));
        }
        let per_append = started.elapsed() / n;

        let mut probe = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("probe"))
            .unwrap();
        let started = std::time::Instant::now();
        for _ in 0..n {
            probe.write_all(b"x").unwrap();
            probe.sync_data().unwrap();
        }
        let per_sync = started.elapsed() / n;
        let started = std::time::Instant::now();
        for _ in 0..n {
            probe.write_all(b"x").unwrap();
            probe.flush().unwrap();
        }
        let per_flush = started.elapsed() / n;
        println!(
            "audit append: {per_append:?}; bare write+sync_data: {per_sync:?}; bare write+flush: {per_flush:?} ({n} each, {})",
            std::env::consts::OS
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Round 12: the lifecycle index ───────────────────────────────────────

    fn lifecycle(event: LifecycleEvent, id: &str, signature: Option<&str>) -> LifecycleEventRecord {
        LifecycleEventRecord {
            event_type: event,
            timestamp: now_utc_rfc3339(),
            content_hash: "0123456789abcdef".to_string(),
            verdict_on_record: Some(VerdictOnRecord::Approved),
            verdict_on_record_key: Some(VerificationKeyKind::AuditTrailId),
            transaction_sha256: None,
            audit_trail_id: Some(id.to_string()),
            transaction_signature: signature.map(String::from),
            reported_by: Some("bridge".to_string()),
            detail: None,
            observed_by_graphite: false,
            sequence_anomalies: Vec::new(),
        }
    }

    /// Rows are found by any of the three keys, in file order, from the
    /// index maintained on append and rebuilt at open.
    /// Round 19 (F-19-23): a record appended after a torn write is not
    /// joined onto the fragment, and it is found after a restart.
    #[test]
    fn a_record_after_a_torn_line_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!(
            "graphite-r19-torn-{}-{}",
            std::process::id(),
            now_utc_rfc3339().replace([':', '.'], "-")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = audit_path(&dir);
        std::fs::write(&path, b"{\"timestamp\": \"torn").unwrap();
        let log = AuditLog::open(&path).unwrap();
        let mut rec = rec("after-torn");
        rec.transaction_sha256 = Some("ab".repeat(32));
        assert!(log.append(&rec));
        log.wait_for_index_jobs();
        drop(log);
        let reopened = AuditLog::open(&path).unwrap();
        let found = reopened.find_verification(VerificationKey::AuditTrailId("after-torn"));
        assert!(
            found.is_some(),
            "the record after the fragment is found after a restart"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Round 19 (F-19-23): a line of invalid UTF-8 skips one line, not the
    /// rest of the file.
    #[test]
    fn an_invalid_utf8_line_does_not_hide_the_records_after_it() {
        let dir = std::env::temp_dir().join(format!(
            "graphite-r19-utf8-{}-{}",
            std::process::id(),
            now_utc_rfc3339().replace([':', '.'], "-")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = audit_path(&dir);
        let rec = rec("after-bad-bytes");
        let mut bytes = vec![0xffu8, 0xfe, b'\n'];
        bytes.extend_from_slice(serde_json::to_string(&rec).unwrap().as_bytes());
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(
            log.count_verifications(VerificationKey::AuditTrailId("after-bad-bytes")),
            (1, 0)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bound_history_keeps_the_first_and_the_latest_rows() {
        let rows: Vec<usize> = (0..200).collect();
        let kept = bound_history(rows);
        assert_eq!(kept.len(), MAX_LIFECYCLE_HISTORY);
        assert_eq!(kept[0], 0);
        assert_eq!(
            *kept.last().unwrap(),
            199,
            "the newest row survives the bound"
        );
    }

    #[test]
    fn lifecycle_history_is_indexed_on_append_and_rebuilt_at_open() {
        let dir = std::env::temp_dir().join(format!(
            "graphite-lc-index-{}-{}",
            std::process::id(),
            now_utc_rfc3339().replace([':', '.'], "-")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        assert!(log.append_lifecycle(&lifecycle(LifecycleEvent::Signing, "gr-1", None)));
        assert!(log.append_lifecycle(&lifecycle(
            LifecycleEvent::Submission,
            "gr-1",
            Some("sigone")
        )));
        assert!(log.append_lifecycle(&lifecycle(LifecycleEvent::Signing, "gr-2", None)));
        let by_id = log.lifecycle_history(LifecycleKey {
            audit_trail_id: Some("gr-1"),
            ..Default::default()
        });
        assert_eq!(by_id.len(), 2);
        assert_eq!(by_id[0].event_type, LifecycleEvent::Signing);
        assert_eq!(by_id[1].event_type, LifecycleEvent::Submission);
        let by_sig = log.lifecycle_history(LifecycleKey {
            transaction_signature: Some("sigone"),
            ..Default::default()
        });
        assert_eq!(by_sig.len(), 1);
        assert!(log
            .lifecycle_history(LifecycleKey {
                audit_trail_id: Some("gr-9"),
                ..Default::default()
            })
            .is_empty());
        assert!(log.lifecycle_history(LifecycleKey::default()).is_empty());

        // A fresh handle rebuilds the index from the file.
        log.wait_for_index_jobs();
        drop(log);
        let reopened = AuditLog::open(&path).unwrap();
        let by_id = reopened.lifecycle_history(LifecycleKey {
            audit_trail_id: Some("gr-1"),
            ..Default::default()
        });
        assert_eq!(by_id.len(), 2);
        // A verification row under the same id is not a lifecycle row.
        assert!(by_id
            .iter()
            .all(|r| r.event_type != LifecycleEvent::Verification));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A lifecycle that straddles a rotation is still found (from the newest
    /// archive), and the per-key history is bounded.
    #[test]
    fn lifecycle_history_survives_one_rotation_and_is_bounded() {
        let dir = std::env::temp_dir().join(format!(
            "graphite-lc-rot-{}-{}",
            std::process::id(),
            now_utc_rfc3339().replace([':', '.'], "-")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        // Rotate at 4 KB: a handful of rows.
        let log = AuditLog::open_with_rotation(&path, 4096, 0).unwrap();
        assert!(log.append_lifecycle(&lifecycle(LifecycleEvent::Signing, "gr-r", None)));
        assert!(log.append_lifecycle(&lifecycle(LifecycleEvent::Submission, "gr-r", Some("sigr"))));
        // Push the file over the threshold with unrelated rows: exactly one
        // rotation, which is the case this lookup covers.
        let mut i = 0;
        while log.health().rotations_ok == 0 {
            assert!(log.append_lifecycle(&lifecycle(
                LifecycleEvent::Signing,
                &format!("gr-filler-{i}"),
                None
            )));
            i += 1;
            assert!(i < 100, "the file never rotated");
        }
        assert_eq!(log.health().rotations_ok, 1, "{:?}", log.health());
        let history = log.lifecycle_history(LifecycleKey {
            audit_trail_id: Some("gr-r"),
            ..Default::default()
        });
        assert_eq!(history.len(), 2, "found in the newest archive");
        assert_eq!(history[1].transaction_signature.as_deref(), Some("sigr"));

        // Bounded: a key with more rows than the cap reports the cap.
        log.wait_for_index_jobs();
        drop(log);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        for _ in 0..(MAX_LIFECYCLE_HISTORY + 20) {
            assert!(log.append_lifecycle(&lifecycle(
                LifecycleEvent::Confirmation,
                "gr-many",
                Some("sigmany")
            )));
        }
        let history = log.lifecycle_history(LifecycleKey {
            audit_trail_id: Some("gr-many"),
            ..Default::default()
        });
        assert_eq!(history.len(), MAX_LIFECYCLE_HISTORY);
        std::fs::remove_dir_all(&dir).ok();
    }
    // ── R-M11 (Round 28): the archives answer from a persisted index ────

    fn index_builds(log: &AuditLog) -> u64 {
        log.archive_index_builds.load(Ordering::Relaxed)
    }

    fn archive_scans(log: &AuditLog) -> u64 {
        log.archive_scans.load(Ordering::Relaxed)
    }

    /// Write `lines` as a rotated archive named for `seq`, as rotation would
    /// have left it.
    fn write_archive(dir: &Path, seq: u32, lines: &[String]) -> PathBuf {
        let path = dir.join(format!("audit.jsonl.{:013}-{seq:06}", 1_700_000_000_000u64));
        let mut body = String::new();
        for l in lines {
            body.push_str(l);
            body.push('\n');
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    fn line_of<T: serde::Serialize>(r: &T) -> String {
        serde_json::to_string(r).unwrap()
    }

    fn index_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("audit.jsonl-index"))
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// Three archives: the first holds 300 verifications of distinct ids
    /// (so the binary search crosses many entries), the second and third
    /// verifications of one transaction and lifecycle rows.
    fn three_archives(dir: &Path) -> Vec<PathBuf> {
        let mut first: Vec<String> = (0..300)
            .map(|i| {
                line_of(&rec_with(
                    &format!("gr-a{i:03}"),
                    &format!("c{i:015x}"),
                    "P",
                    i % 3 == 0,
                ))
            })
            .collect();
        first.push(line_of(&counted("gr-t0", true)));
        let second = vec![
            line_of(&counted("gr-t1", false)),
            line_of(&lifecycle(LifecycleEvent::Signing, "gr-t1", None)),
            line_of(&counted("gr-t2", true)),
        ];
        let third = vec![
            line_of(&counted("gr-t3", true)),
            line_of(&lifecycle(
                LifecycleEvent::Submission,
                "gr-t3",
                Some("sig-t3"),
            )),
        ];
        vec![
            write_archive(dir, 0, &first),
            write_archive(dir, 1, &second),
            write_archive(dir, 2, &third),
        ]
    }

    /// R-M11: a count, a lookup and a lifecycle history over rotated
    /// archives each answer from the archives' persisted indexes. Every
    /// archive is parsed once, to build its index, and never scanned by a
    /// lookup; a restart reads the indexes back instead of parsing anything.
    ///
    /// Before Round 28 each of these calls was a pass over every archive
    /// (`archive_scans` here); the answers are the same.
    #[test]
    fn archive_lookups_answer_from_a_persisted_index_across_restart() {
        let dir = counts_dir("rm11-index");
        let archives = three_archives(&dir);
        let path = audit_path(&dir);
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        let answers = |log: &AuditLog| {
            assert_eq!(log.count_verifications(tx), (3, 1));
            assert_eq!(
                log.count_verifications(VerificationKey::ContentHash("00000000000000aa")),
                (3, 1)
            );
            for i in [0usize, 1, 150, 298, 299] {
                let id = format!("gr-a{i:03}");
                let found = log
                    .find_verification(VerificationKey::AuditTrailId(&id))
                    .expect("an archived record must be found");
                assert_eq!(found.audit_trail_id, id);
                assert_eq!(found.approved, i % 3 == 0);
                assert_eq!(
                    log.count_verifications(VerificationKey::AuditTrailId(&id)),
                    if i % 3 == 0 { (1, 0) } else { (0, 1) }
                );
            }
            // The newest record under the digest is in the newest archive.
            assert_eq!(log.find_verification(tx).unwrap().audit_trail_id, "gr-t3");
            assert!(log
                .find_verification(VerificationKey::AuditTrailId("gr-nowhere"))
                .is_none());
            assert_eq!(
                log.count_verifications(VerificationKey::AuditTrailId("gr-nowhere")),
                (0, 0)
            );
            let history = log.lifecycle_history(LifecycleKey {
                audit_trail_id: Some("gr-t3"),
                transaction_sha256: None,
                transaction_signature: Some("sig-t3"),
            });
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].event_type, LifecycleEvent::Submission);
        };
        {
            let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
            answers(&log);
            assert_eq!(
                index_builds(&log),
                3,
                "each archive is parsed once, to build its index"
            );
            assert_eq!(
                archive_scans(&log),
                0,
                "no lookup may scan an indexed archive"
            );
            answers(&log);
            assert_eq!(index_builds(&log), 3);
            assert_eq!(archive_scans(&log), 0);
        }
        let files = index_files(&dir);
        assert_eq!(files.len(), 3, "one index file per archive: {files:?}");
        for a in &archives {
            let name = format!("{}.idx", a.file_name().unwrap().to_str().unwrap());
            assert!(files.iter().any(|f| f.ends_with(&name)), "{name} missing");
        }
        // Restart: the indexes are read back and checked, not rebuilt.
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        answers(&log);
        assert_eq!(
            index_builds(&log),
            0,
            "a restart must not reparse an indexed archive"
        );
        assert_eq!(archive_scans(&log), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An index that does not check against its archive is never answered
    /// from. A flipped byte, a truncated file, another version, and an
    /// archive whose bytes changed under an index of the same length are
    /// each rebuilt from the archive, and the answers are the archive's.
    #[test]
    fn an_archive_index_that_does_not_check_is_rebuilt() {
        let dir = counts_dir("rm11-check");
        let archives = three_archives(&dir);
        let path = audit_path(&dir);
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        {
            let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
            assert_eq!(log.count_verifications(tx), (3, 1));
        }
        let files = index_files(&dir);
        assert_eq!(files.len(), 3);
        // 1. A flipped byte inside the entries: the trailer disagrees.
        let mut bytes = std::fs::read(&files[0]).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&files[0], &bytes).unwrap();
        // 2. A truncated file.
        let bytes = std::fs::read(&files[1]).unwrap();
        std::fs::write(&files[1], &bytes[..bytes.len() - 7]).unwrap();
        // 3. Another format version, with the trailer recomputed so only
        //    the version is wrong.
        let mut bytes = std::fs::read(&files[2]).unwrap();
        bytes[8..12].copy_from_slice(&(archive_index::VERSION + 1).to_le_bytes());
        let n = bytes.len();
        let trailer: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(&bytes[..n - 32]).into()
        };
        bytes[n - 32..].copy_from_slice(&trailer);
        std::fs::write(&files[2], &bytes).unwrap();
        {
            let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
            assert_eq!(log.count_verifications(tx), (3, 1));
            assert_eq!(
                index_builds(&log),
                3,
                "every index that does not check is rebuilt"
            );
            assert_eq!(archive_scans(&log), 0);
        }
        // 4. The archive changed and kept its length, which a length check
        //    alone would miss: the newest archive's record moves to another
        //    transaction digest of the same width.
        let body = std::fs::read_to_string(&archives[2]).unwrap();
        let other = "b".repeat(64);
        std::fs::write(&archives[2], body.replacen(COUNTED_TX, &other, 1)).unwrap();
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert_eq!(
            log.count_verifications(tx),
            (2, 1),
            "the count must be the archive's, not a stale index's"
        );
        assert_eq!(
            log.count_verifications(VerificationKey::TransactionSha256(&other)),
            (1, 0)
        );
        assert_eq!(index_builds(&log), 1, "only the changed archive is rebuilt");
        assert_eq!(archive_scans(&log), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An indexed offset that does not read back as its record (the archive
    /// changed under an index already checked in this process) is never the
    /// answer. The archive is scanned, the right record returned, and the
    /// index discarded so the next lookup rebuilds it.
    #[test]
    fn an_indexed_archive_offset_that_does_not_read_back_is_never_an_answer() {
        let dir = counts_dir("rm11-readback");
        let a = line_of(&rec_with("gr-x1", "00000000000000c1", "P", true));
        let b = line_of(&rec_with("gr-x2", "00000000000000c2", "P", true));
        assert_eq!(a.len(), b.len(), "the swap must keep the archive's length");
        let archive = write_archive(&dir, 0, &[a.clone(), b.clone()]);
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let x1 = VerificationKey::AuditTrailId("gr-x1");
        assert_eq!(log.find_verification(x1).unwrap().audit_trail_id, "gr-x1");
        assert_eq!(index_builds(&log), 1);
        // Swap the two lines in place. The length is the same, so the
        // checked index stays cached, and its offset for gr-x1 now holds
        // gr-x2.
        std::fs::write(&archive, format!("{b}\n{a}\n")).unwrap();
        let found = log
            .find_verification(x1)
            .expect("the scan finds the record");
        assert_eq!(found.audit_trail_id, "gr-x1");
        assert_eq!(archive_scans(&log), 1, "a broken offset scans the archive");
        assert!(index_files(&dir).is_empty(), "and discards the index");
        // The next lookup checks the archive again and rebuilds.
        assert_eq!(log.find_verification(x1).unwrap().audit_trail_id, "gr-x1");
        assert_eq!(index_builds(&log), 2);
        assert_eq!(archive_scans(&log), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An index that cannot be written leaves the archive scanned, with the
    /// right answer, and is not rebuilt on every lookup: a parse per lookup
    /// would cost more than the scan it replaces.
    #[test]
    fn an_unwritable_archive_index_falls_back_to_one_scan_per_lookup() {
        let dir = counts_dir("rm11-unwritable");
        three_archives(&dir);
        // A file where the index directory would be.
        std::fs::write(dir.join("audit.jsonl-index"), b"not a directory").unwrap();
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(index_builds(&log), 3);
        assert_eq!(archive_scans(&log), 3);
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(
            index_builds(&log),
            3,
            "an index that cannot be written is not retried"
        );
        assert_eq!(archive_scans(&log), 6);
        assert_eq!(
            log.find_verification(VerificationKey::AuditTrailId("gr-a150"))
                .unwrap()
                .audit_trail_id,
            "gr-a150"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pruning an archive removes its index with it, and the counts stop
    /// including it.
    #[test]
    fn pruning_an_archive_removes_its_index() {
        let dir = counts_dir("rm11-prune");
        let path = audit_path(&dir);
        let log = AuditLog::open_with_rotation(&path, 1, 2).unwrap();
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        for i in 0..2 {
            assert!(log.append(&counted(&format!("gr-p{i}"), true)));
        }
        assert_eq!(log.count_verifications(tx), (2, 0));
        log.wait_for_index_jobs();
        assert_eq!(index_files(&dir).len(), 2);
        assert!(log.append(&counted("gr-p2", false)));
        let archives = archives_in(&dir);
        assert_eq!(archives.len(), 2, "retention keeps two archives");
        assert_eq!(log.count_verifications(tx), (1, 1));
        log.wait_for_index_jobs();
        let names: Vec<String> = archives
            .iter()
            .map(|a| format!("{}.idx", a.file_name().unwrap().to_str().unwrap()))
            .collect();
        let files = index_files(&dir);
        assert_eq!(files.len(), 2, "{files:?}");
        for f in &files {
            let name = f.file_name().unwrap().to_str().unwrap().to_string();
            assert!(
                names.contains(&name),
                "{name} describes an archive no longer on disk"
            );
        }
        assert_eq!(archive_scans(&log), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R-M11's cost, measured: three 64 MiB archives counted by scanning
    /// (the pre-Round-28 path, forced here by an unwritable index
    /// directory), by building their indexes, from the indexes, and after a
    /// restart. Prints the numbers the round report records. Run with
    /// `cargo test --release --lib -- --ignored archive_index_cost --nocapture`.
    #[test]
    #[ignore = "benchmark: writes 192 MiB of archives"]
    fn archive_index_cost_on_64_mib_archives() {
        use std::time::Instant;
        let dir = counts_dir("rm11-cost");
        let mut per_archive = 0usize;
        for seq in 0..3u32 {
            let mut body = String::with_capacity(DEFAULT_ROTATE_BYTES as usize + 4096);
            let mut i = 0usize;
            while (body.len() as u64) < DEFAULT_ROTATE_BYTES {
                let mut r = rec_with(
                    &format!("gr-{seq}-{i:08}"),
                    &format!("{:016x}", i % 4096),
                    "P",
                    i.is_multiple_of(2),
                );
                r.transaction_sha256 = Some(format!("{:064x}", seq as usize * 10_000_000 + i));
                body.push_str(&line_of(&r));
                body.push('\n');
                i += 1;
            }
            // One record of the counted transaction per archive.
            body.push_str(&line_of(&counted(&format!("gr-c{seq}"), true)));
            body.push('\n');
            per_archive = i + 1;
            let path = dir.join(format!("audit.jsonl.{:013}-{seq:06}", 1_700_000_000_000u64));
            std::fs::write(path, body).unwrap();
        }
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        let median = |mut v: Vec<f64>| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let ms = |t: Instant| t.elapsed().as_secs_f64() * 1000.0;

        let blocker = dir.join("audit.jsonl-index");
        std::fs::write(&blocker, b"x").unwrap();
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let first = Instant::now();
        assert_eq!(log.count_verifications(tx), (3, 0));
        let failed_build = ms(first);
        let scans: Vec<f64> = (0..3)
            .map(|_| {
                let t = Instant::now();
                assert_eq!(log.count_verifications(tx), (3, 0));
                ms(t)
            })
            .collect();
        let scan = median(scans);
        drop(log);
        std::fs::remove_file(&blocker).unwrap();

        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let t = Instant::now();
        assert_eq!(log.count_verifications(tx), (3, 0));
        let build = ms(t);
        let counts: Vec<f64> = (0..200)
            .map(|_| {
                let t = Instant::now();
                assert_eq!(log.count_verifications(tx), (3, 0));
                ms(t)
            })
            .collect();
        let misses: Vec<f64> = (0..200)
            .map(|_| {
                let t = Instant::now();
                assert!(log
                    .find_verification(VerificationKey::AuditTrailId("gr-nowhere"))
                    .is_none());
                ms(t)
            })
            .collect();
        assert_eq!(archive_scans(&log), 0);
        log.wait_for_index_jobs();
        drop(log);

        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let t = Instant::now();
        assert_eq!(log.count_verifications(tx), (3, 0));
        let restart = ms(t);
        assert_eq!(index_builds(&log), 0);
        let index_bytes: u64 = index_files(&dir)
            .iter()
            .map(|f| std::fs::metadata(f).unwrap().len())
            .sum();
        eprintln!(
            "R-M11 cost over 3 archives of 64 MiB ({per_archive} records each):\n  \
             scan count (pre-Round-28 path): {scan:.1} ms (median of 3; first with a failed build {failed_build:.1} ms)\n  \
             first count, building 3 indexes: {build:.1} ms\n  \
             indexed count: {:.3} ms (median of 200)\n  \
             indexed miss: {:.3} ms (median of 200)\n  \
             first count after a restart (hash check): {restart:.1} ms\n  \
             index files: {index_bytes} bytes",
            median(counts),
            median(misses),
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rotation hands the active file's indexes to the archive it rotated
    /// into: the archive's index is written from them on a background
    /// thread, with no parse of the archive, and answers exactly as a
    /// parse would have.
    #[test]
    fn a_rotated_archive_is_indexed_from_the_active_indexes_without_a_parse() {
        let dir = counts_dir("rm11-rotate");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        for (i, approved) in [true, false, true].into_iter().enumerate() {
            assert!(log.append(&counted(&format!("gr-r{i}"), approved)));
        }
        assert!(log.append_lifecycle(&lifecycle(LifecycleEvent::Signing, "gr-r2", None)));
        log.wait_for_index_jobs();
        assert_eq!(archives_in(&dir).len(), 4);
        assert_eq!(
            index_files(&dir).len(),
            4,
            "every rotated archive is indexed"
        );
        assert_eq!(log.count_verifications(tx), (2, 1));
        assert_eq!(
            log.find_verification(VerificationKey::AuditTrailId("gr-r1"))
                .map(|r| r.approved),
            Some(false)
        );
        let history = log.lifecycle_history(LifecycleKey {
            audit_trail_id: Some("gr-r2"),
            transaction_sha256: None,
            transaction_signature: None,
        });
        assert_eq!(history.len(), 1);
        assert_eq!(index_builds(&log), 0, "no archive may be parsed");
        assert_eq!(archive_scans(&log), 0);
        // The same indexes, checked by a fresh process.
        log.wait_for_index_jobs();
        drop(log);
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        assert_eq!(log.count_verifications(tx), (2, 1));
        assert_eq!(index_builds(&log), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The start-up warm-up checks or builds every archive's index before
    /// any lookup needs it, and removes index files no archive needs: a
    /// temporary file a stopped process left and the index of an archive
    /// that is gone.
    #[test]
    fn warming_the_archive_indexes_checks_every_archive_and_sweeps_stale_files() {
        let dir = counts_dir("rm11-warm");
        three_archives(&dir);
        let index_dir = dir.join("audit.jsonl-index");
        std::fs::create_dir_all(&index_dir).unwrap();
        let orphan = index_dir.join("audit.jsonl.0000000000001-000000.idx");
        let temp = index_dir.join("audit.jsonl.0000000000002-000000.idx.tmp-1-0");
        std::fs::write(&orphan, b"orphan").unwrap();
        std::fs::write(&temp, b"temp").unwrap();
        // A backup an earlier version indexed as an archive (Round 29).
        std::fs::write(dir.join("audit.jsonl.bak"), b"backup").unwrap();
        let backup_index = index_dir.join("audit.jsonl.bak.idx");
        std::fs::write(&backup_index, b"index of a backup").unwrap();
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        log.warm_archive_indexes_in_background();
        log.wait_for_index_jobs();
        assert_eq!(index_builds(&log), 3);
        assert!(!orphan.exists(), "an index of no archive is removed");
        assert!(
            !backup_index.exists(),
            "an index of a non-archive is removed"
        );
        assert!(
            !temp.exists(),
            "a stopped write's temporary file is removed"
        );
        assert_eq!(index_files(&dir).len(), 3);
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(index_builds(&log), 3, "the lookup found every index ready");
        assert_eq!(archive_scans(&log), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Round 29 (audit 2026-10-20): the audit trail ───────────────────────

    fn archive_holding(archives: &[PathBuf], id: &str) -> Option<PathBuf> {
        archives
            .iter()
            .find(|a| {
                std::fs::read_to_string(a)
                    .unwrap_or_default()
                    .contains(&format!("\"audit_trail_id\":\"{id}\""))
            })
            .cloned()
    }

    /// A rotation after the wall clock stepped back names its archive NEWER
    /// than every archive on disk. The stamp was the clock alone, so the new
    /// archive sorted as the oldest: with `max_archives == 1` pruning
    /// deleted it on the spot, and the record it held was gone.
    ///
    /// Deliberate break: with the stamp reverted to `now` this test fails
    /// (the record just written is pruned with its archive).
    #[test]
    fn a_backwards_clock_never_makes_the_newest_archive_the_oldest() {
        let dir = counts_dir("clock-back");
        // An archive written while the clock read far in the future.
        let future = dir.join("audit.jsonl.4000000000000-000000");
        std::fs::write(&future, format!("{}\n", line_of(&rec("gr-future")))).unwrap();
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 1).unwrap();
        assert!(log.append(&rec("gr-new")));
        let archives = log.archives();
        assert_eq!(archives.len(), 1, "retention keeps one archive");
        assert_eq!(
            archive_holding(&archives, "gr-new").as_ref(),
            Some(&archives[0]),
            "the archive just written is the newest and survives pruning: {archives:?}"
        );
        assert!(log
            .find_verification(VerificationKey::AuditTrailId("gr-new"))
            .is_some());
        let name = archives[0].file_name().unwrap().to_str().unwrap();
        let (stamp, _, _) = parse_archive_name("audit.jsonl", name).unwrap();
        assert!(stamp > 4_000_000_000_000, "{name}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Stamps strictly increase within a process even when the clock
    /// does not move or moves back, and the archive order is numeric.
    #[test]
    fn archive_stamps_increase_and_order_numerically() {
        let dir = counts_dir("stamps");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();
        let a = log.next_archive_path(2_000_000_000_000).unwrap();
        let b = log.next_archive_path(1_000_000_000_000).unwrap();
        let order = |p: &PathBuf| {
            parse_archive_name("audit.jsonl", p.file_name().unwrap().to_str().unwrap()).unwrap()
        };
        assert!(order(&b) > order(&a), "{a:?} then {b:?}");
        // Numeric, not lexical: a seventh digit of sequence sorts after six.
        let six = parse_archive_name("audit.jsonl", "audit.jsonl.1700000000000-999999").unwrap();
        let seven = parse_archive_name("audit.jsonl", "audit.jsonl.1700000000000-1000000").unwrap();
        assert!(seven > six);
        let probed =
            parse_archive_name("audit.jsonl", "audit.jsonl.1700000000000-000001-0002").unwrap();
        assert!(
            probed > parse_archive_name("audit.jsonl", "audit.jsonl.1700000000000-000001").unwrap()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Only the names rotation generates are archives. Any `audit.jsonl.*`
    /// used to be one: an operator's backup was counted on top of the
    /// trail it copies, and sorted as the newest archive.
    ///
    /// Deliberate break: with the prefix-only filter restored the totals
    /// below double and the backup is listed.
    #[test]
    fn only_generated_names_are_archives() {
        for (name, archive) in [
            ("audit.jsonl.1700000000000-000000", true),
            ("audit.jsonl.1700000000000-000000-0001", true),
            ("audit.jsonl.1-1234567", true),
            ("audit.jsonl.bak", false),
            ("audit.jsonl.", false),
            ("audit.jsonl.1700000000000", false),
            ("audit.jsonl.1700000000000-00001", false),
            ("audit.jsonl.1700000000000-000000-001", false),
            ("audit.jsonl.1700000000000-000000-0000", false),
            ("audit.jsonl.1700000000000-000000.bak", false),
            ("audit.jsonl.1700000000000-000000-0001-0001", false),
            ("audit.jsonl.+1700000000000-000000", false),
            ("audit.jsonl-index", false),
            ("other.jsonl.1700000000000-000000", false),
        ] {
            assert_eq!(
                parse_archive_name("audit.jsonl", name).is_some(),
                archive,
                "{name}"
            );
        }
        let dir = counts_dir("strict-names");
        let path = audit_path(&dir);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        for i in 0..3 {
            assert!(log.append(&rec(&format!("gr-{i}"))));
        }
        std::fs::copy(&path, dir.join("audit.jsonl.bak")).unwrap();
        std::fs::copy(&path, dir.join("audit.jsonl.1700000000000-000000.swp")).unwrap();
        std::fs::create_dir(dir.join("audit.jsonl.1700000000000-000001")).unwrap();
        assert!(log.archives().is_empty(), "{:?}", log.archives());
        assert_eq!(log.health().archive_count, 0);
        let (_, _, total, _) = log.read_tail_filtered(10, AuditSelector::All);
        assert_eq!(total, 3, "a backup is not more trail");
        assert_eq!(
            log.count_verifications(VerificationKey::AuditTrailId("gr-1")),
            (1, 0)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every probed name taken: an error, never a name that exists (the
    /// rename would replace it). The loop used to return the last probe.
    #[test]
    fn an_archive_name_is_never_one_that_exists() {
        let dir = counts_dir("probe-limit");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 1, 0).unwrap();
        const STAMP: u128 = 1_700_000_000_000;
        // Directories are not archives, so they do not raise the stamp
        // floor; they only occupy the names.
        std::fs::create_dir(dir.join(format!("audit.jsonl.{STAMP}-000000"))).unwrap();
        for extra in 1..=MAX_ARCHIVE_NAME_PROBES {
            std::fs::create_dir(dir.join(format!("audit.jsonl.{STAMP}-000000-{extra:04}")))
                .unwrap();
        }
        let err = log.next_archive_path(STAMP).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A write reported as failed leaves nothing behind. The device sync is
    /// made to fail after the whole line was written — the case where the
    /// record used to be complete on disk and, after a restart, indexed and
    /// counted as a verdict Graphite had refused to stand behind.
    ///
    /// Deliberate break: without the truncation the reopened log finds
    /// `gr-unacked` and counts it.
    #[test]
    fn a_failed_append_is_removed_from_the_trail() {
        let dir = counts_dir("failed-append");
        let path = audit_path(&dir);
        let key = VerificationKey::TransactionSha256(COUNTED_TX);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert!(log.append(&counted("gr-0", true)));
        let before = std::fs::metadata(&path).unwrap().len();
        log.faults.store(FAULT_SYNC, Ordering::SeqCst);
        assert!(!log.append(&counted("gr-unacked", false)));
        log.faults.store(0, Ordering::SeqCst);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
        assert_eq!(log.count_verifications(key), (1, 0));
        assert_eq!(count_scans(&log), 0, "the counts still match the file");
        assert!(log
            .find_verification(VerificationKey::AuditTrailId("gr-unacked"))
            .is_none());
        assert!(log.append(&counted("gr-1", true)));
        log.wait_for_index_jobs();
        drop(log);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert!(log
            .find_verification(VerificationKey::AuditTrailId("gr-unacked"))
            .is_none());
        assert_eq!(log.count_verifications(key), (2, 0));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// When the failed write cannot be undone either, no reader sees it and
    /// nothing is appended after it until it is removed — appending after it
    /// would make it permanent. Once the truncation succeeds, appends resume
    /// and the record is gone for good.
    ///
    /// Deliberate break: without the read limit the in-process count and
    /// lookup return `gr-unacked`; without the retry it survives a restart.
    #[test]
    fn a_failed_append_that_cannot_be_undone_is_never_read_and_blocks_appends() {
        let dir = counts_dir("failed-undo");
        let path = audit_path(&dir);
        let key = VerificationKey::TransactionSha256(COUNTED_TX);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert!(log.append(&counted("gr-0", true)));
        let before = std::fs::metadata(&path).unwrap().len();
        log.faults
            .store(FAULT_SYNC | FAULT_TRUNCATE, Ordering::SeqCst);
        assert!(!log.append(&counted("gr-unacked", false)));
        assert!(
            std::fs::metadata(&path).unwrap().len() > before,
            "the line is on disk"
        );
        assert_eq!(log.count_verifications(key), (1, 0));
        assert_eq!(count_scans(&log), 0);
        assert!(log
            .find_verification(VerificationKey::AuditTrailId("gr-unacked"))
            .is_none());
        let (_, _, total, _) = log.read_tail_filtered(10, AuditSelector::All);
        assert_eq!(total, 1);
        // Still cannot cut: refused.
        log.faults.store(FAULT_TRUNCATE, Ordering::SeqCst);
        assert!(!log.append(&counted("gr-blocked", true)));
        // A forced recount stops at the boundary too.
        log.active_counts.lock().unwrap().len = 0;
        assert_eq!(log.count_verifications(key), (1, 0));
        log.faults.store(0, Ordering::SeqCst);
        assert!(log.append(&counted("gr-1", true)));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("gr-unacked"), "{text}");
        assert!(!text.contains("gr-blocked"), "{text}");
        assert_eq!(log.count_verifications(key), (2, 0));
        log.wait_for_index_jobs();
        drop(log);
        let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
        assert_eq!(log.count_verifications(key), (2, 0));
        assert_eq!(log.health().writes_failed, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rotation that renamed the active file away and could neither open
    /// a fresh one nor rename it back refuses appends, instead of writing
    /// them into the archive through the old handle; appends resume when a
    /// fresh active file can be opened.
    ///
    /// Deliberate break: without the refusal `gr-1` lands in the archive
    /// (whose length then changes) and is counted.
    #[test]
    fn a_rotation_that_cannot_reopen_never_appends_into_an_archive() {
        let dir = counts_dir("detached");
        let path = audit_path(&dir);
        let key = VerificationKey::TransactionSha256(COUNTED_TX);
        let log = AuditLog::open_with_rotation(&path, 1, 0).unwrap();
        log.faults
            .store(FAULT_REOPEN | FAULT_RENAME_BACK, Ordering::SeqCst);
        assert!(
            log.append(&counted("gr-0", true)),
            "written before rotating"
        );
        assert!(!path.exists(), "renamed away, nothing reopened");
        let archives = log.archives();
        assert_eq!(archives.len(), 1);
        let archived = std::fs::read(&archives[0]).unwrap();
        assert!(!log.append(&counted("gr-1", false)));
        assert_eq!(std::fs::read(&archives[0]).unwrap(), archived);
        assert_eq!(log.count_verifications(key), (1, 0));
        let (_, _, total, _) = log.read_tail_filtered(10, AuditSelector::All);
        assert_eq!(total, 1);
        log.faults.store(0, Ordering::SeqCst);
        assert!(log.append(&counted("gr-2", true)));
        assert_eq!(std::fs::read(&archives[0]).unwrap(), archived);
        assert_eq!(log.count_verifications(key), (2, 0));
        assert!(log
            .find_verification(VerificationKey::AuditTrailId("gr-1"))
            .is_none());
        assert!(log
            .find_verification(VerificationKey::AuditTrailId("gr-2"))
            .is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An archive index that could not be had is tried again once its wait
    /// is over, instead of never for the life of the process.
    ///
    /// Deliberate break: with the old sticky state the last count scans
    /// again and builds nothing.
    #[test]
    fn an_unavailable_archive_index_is_retried_after_its_wait() {
        let dir = counts_dir("index-retry");
        three_archives(&dir);
        let blocker = dir.join("audit.jsonl-index");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(index_builds(&log), 3);
        std::fs::remove_file(&blocker).unwrap();
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(index_builds(&log), 3, "not before the wait is over");
        assert_eq!(archive_scans(&log), 6);
        for state in log.archive_indexes.lock().unwrap().values_mut() {
            match state {
                IndexState::Unavailable {
                    failures, retry_at, ..
                } => {
                    assert_eq!(*failures, 1);
                    *retry_at = std::time::Instant::now();
                }
                IndexState::Ready(_) => panic!("no index could have been built"),
            }
        }
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(index_builds(&log), 6, "retried and built");
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(archive_scans(&log), 6, "answered from the indexes since");
        assert_eq!(index_retry_wait(1), INDEX_RETRY_FIRST);
        assert_eq!(index_retry_wait(2), INDEX_RETRY_FIRST * 2);
        assert_eq!(index_retry_wait(40), INDEX_RETRY_MAX);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An archive's cached statistics keep a bounded number of program ids,
    /// however many distinct ids its records carry, and the frequent ones
    /// stay exact.
    ///
    /// Deliberate break: without `bounded` the cache holds all 401 ids.
    #[test]
    fn archive_program_statistics_are_bounded() {
        let dir = counts_dir("program-bound");
        let mut lines: Vec<String> = (0..400)
            .map(|i| {
                line_of(&rec_with(
                    &format!("gr-{i}"),
                    "h",
                    &format!("prog-{i:04}"),
                    true,
                ))
            })
            .collect();
        for i in 0..5 {
            lines.push(line_of(&rec_with(&format!("gr-hot-{i}"), "h", "HOT", true)));
        }
        let archive = write_archive(&dir, 0, &lines);
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        let observed = log.observations_by_program();
        assert_eq!(observed.get("HOT"), Some(&5));
        assert_eq!(observed.len(), MAX_PROGRAMS_PER_ARCHIVE);
        let cache = log.archive_stats.lock().unwrap();
        let stats = cache.get(&archive).unwrap();
        assert_eq!(stats.by_program.len(), MAX_PROGRAMS_PER_ARCHIVE);
        assert_eq!(
            stats.by_program.values().sum::<usize>() + stats.other_programs,
            405
        );
        assert_eq!(stats.approved, 405, "the totals are not bounded");
        drop(cache);
        assert_eq!(
            log.observations_by_program(),
            observed,
            "cached answer is the same"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An index whose counts disagree with the archive record it points at
    /// is not believed: the archive is scanned and the index discarded. The
    /// forged index here passes every hash check (built over the real
    /// archive bytes), as one written by anyone with access to the data
    /// directory would.
    ///
    /// Deliberate break: without `index_entry_is_plausible` the count is
    /// the forged (0, 7) for that archive.
    #[test]
    fn an_index_whose_counts_disagree_with_its_archive_is_not_believed() {
        let dir = counts_dir("forged-index");
        let archives = three_archives(&dir);
        let tx = VerificationKey::TransactionSha256(COUNTED_TX);
        {
            let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
            assert_eq!(log.count_verifications(tx), (3, 1));
        }
        let index_dir = dir.join("audit.jsonl-index");
        let (sha, len) = archive_index::file_sha256(&archives[0]).unwrap();
        let (last, lifecycle, mut counts) = build_indexes(&archives[0]);
        counts.by_key.insert(format!("tx:{COUNTED_TX}"), (0, 7));
        archive_index::write(
            &archive_index::index_path(&index_dir, &archives[0]).unwrap(),
            len,
            &sha,
            archive_index::IndexSource {
                last: &last,
                counts: &counts.by_key,
                lifecycle: &lifecycle,
            },
        )
        .unwrap();
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        assert_eq!(log.count_verifications(tx), (3, 1));
        assert_eq!(archive_scans(&log), 1, "the forged archive was scanned");
        // An absurd count is refused on size alone.
        counts
            .by_key
            .insert(format!("tx:{COUNTED_TX}"), (1_000_000_000, 0));
        archive_index::write(
            &archive_index::index_path(&index_dir, &archives[0]).unwrap(),
            len,
            &sha,
            archive_index::IndexSource {
                last: &last,
                counts: &counts.by_key,
                lifecycle: &lifecycle,
            },
        )
        .unwrap();
        log.wait_for_index_jobs();
        drop(log);
        let log = AuditLog::open_with_rotation(audit_path(&dir), 0, 0).unwrap();
        assert_eq!(log.count_verifications(tx), (3, 1));
        std::fs::remove_dir_all(&dir).ok();
    }
}
