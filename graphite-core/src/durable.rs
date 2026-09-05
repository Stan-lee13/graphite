//! Durability — audit trail persistence for verification results.
//!
//! The semantic-graph/baseline snapshot is handled inside
//! [`crate::verification::GraphiteCore::with_data_dir`]; this module owns the
//! append-only JSONL audit log that the HTTP server writes after every
//! verification. One JSON object per line, flushed per write so a crash loses
//! at most the in-flight request.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
/// `rotate_bytes` it is RENAMED to `audit.jsonl.<unix-millis>` and a fresh
/// active file is started. Archives are retained indefinitely by default
/// (`max_archives == 0`), so the complete trail survives; an operator who
/// needs a hard disk bound sets `GRAPHITE_AUDIT_MAX_ARCHIVES` and accepts
/// that the oldest archives are pruned. Deleting audit history is therefore
/// always an explicit operator decision, never something Graphite does on its
/// own initiative.
#[derive(Debug, Clone)]
pub struct AuditLog {
    file: std::sync::Arc<Mutex<File>>,
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
}

/// A point-in-time view of audit-log health, surfaced by /health and /metrics.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct AuditHealth {
    pub writes_ok: u64,
    pub writes_failed: u64,
    /// Current size of the ACTIVE audit file in bytes (archives excluded).
    pub active_bytes: u64,
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
/// than one that admits the gap. Those four are recorded through
/// `GraphiteCore::record_lifecycle_event` / the server's audit-event endpoint,
/// by the component that actually performed them, keyed to the same
/// `content_hash` so the whole lifecycle reconciles.
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
    /// The network confirmed it. Caller-reported.
    Confirmation,
    /// The transaction reached finalized commitment. Caller-reported.
    Finalization,
}

impl LifecycleEvent {
    /// True for the events Graphite itself witnesses and emits.
    ///
    /// The complement is caller-reported: Graphite has no way to observe it
    /// and must not invent it.
    pub fn is_self_observed(&self) -> bool {
        matches!(
            self,
            LifecycleEvent::Construction
                | LifecycleEvent::Simulation
                | LifecycleEvent::Verification
        )
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
    pub program_id: String,
    pub instruction_name: String,
    pub protocol_name: String,
    pub manifest_version: Option<String>,
    pub approved: bool,
    pub confidence: f64,
    pub risk_status: String,
    pub policy_verdict: String,
    /// L3 simulation verdict as emitted by the layer (passed/failed/inconclusive)
    /// — GAP-2026-08-06-3: the audit trail must reflect the REAL layer states.
    pub l3_status: String,
    /// L8 execution-verification state (always "inconclusive" until Phase 2
    /// wires post-submission verification) — GAP-2026-08-06-3.
    pub l8_status: String,
}

/// A lifecycle event for a stage Graphite does not itself perform.
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

impl AuditLog {
    /// Open (creating if needed) the audit log at `path`. The parent
    /// directory must already exist (callers create the data dir first).
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::open_with_rotation(path, DEFAULT_ROTATE_BYTES, 0)
    }

    /// Open with explicit rotation settings. `rotate_bytes == 0` disables
    /// rotation entirely; `max_archives == 0` keeps every archive (default).
    pub fn open_with_rotation(
        path: impl AsRef<Path>,
        rotate_bytes: u64,
        max_archives: usize,
    ) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file: std::sync::Arc::new(Mutex::new(file)),
            path: Arc::new(path),
            rotate_bytes,
            max_archives,
            writes_ok: Arc::new(AtomicU64::new(0)),
            writes_failed: Arc::new(AtomicU64::new(0)),
            rotation_seq: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Current audit-log health for /health and /metrics.
    pub fn health(&self) -> AuditHealth {
        AuditHealth {
            writes_ok: self.writes_ok.load(Ordering::Relaxed),
            writes_failed: self.writes_failed.load(Ordering::Relaxed),
            active_bytes: std::fs::metadata(self.path.as_ref())
                .map(|m| m.len())
                .unwrap_or(0),
        }
    }

    /// Rotate the active file if it has grown past `rotate_bytes`.
    ///
    /// Called with the append handle already locked, so no writer can append
    /// between the size check and the rename. The rename preserves every
    /// record (P9 — rotation is not deletion); only explicit `max_archives`
    /// pruning removes anything, and that is opt-in.
    /// Build a UNIQUE archive path for a rotation occurring at `stamp`.
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
    /// The monotonic sequence guarantees uniqueness within the process. It is
    /// zero-padded because `prune_archives` decides what is "oldest" by
    /// lexical order, and an unpadded counter would sort `-10` before `-2` and
    /// prune newer history while keeping older.
    fn next_archive_path(&self, stamp: u128) -> PathBuf {
        let seq = self.rotation_seq.fetch_add(1, Ordering::Relaxed);
        let mut archive = self
            .path
            .with_extension(format!("jsonl.{stamp}-{seq:06}"))
            .to_path_buf();

        // Cross-restart safety: the sequence restarts at 0 with the process,
        // so a previous run could in principle have written this exact name in
        // this exact millisecond. Probing is safe here (callers hold the append
        // handle lock, so nothing in this process can race us) and costs one
        // stat on a path taken once per rotation.
        let mut extra = 0u32;
        while archive.exists() && extra < 10_000 {
            extra += 1;
            archive = self
                .path
                .with_extension(format!("jsonl.{stamp}-{seq:06}-{extra:04}"))
                .to_path_buf();
        }
        archive
    }

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
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let archive = self.next_archive_path(stamp);

        // If the rename fails (permissions, cross-device), keep appending to
        // the current file rather than losing the record — an oversized log
        // is strictly better than a dropped audit trail.
        if std::fs::rename(self.path.as_ref(), &archive).is_err() {
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.as_ref())
        {
            Ok(fresh) => {
                *file = fresh;
                tracing::info!("audit log rotated to {}", archive.display());
                self.prune_archives();
            }
            Err(e) => {
                // We already renamed the old file away; try to restore it so
                // no window exists with no audit file at all.
                let _ = std::fs::rename(&archive, self.path.as_ref());
                tracing::error!("audit rotation failed to reopen log: {}", e);
            }
        }
    }

    /// Prune the oldest archives when an explicit retention limit is set.
    /// No-op when `max_archives == 0` (keep everything — the P9 default).
    fn prune_archives(&self) {
        if self.max_archives == 0 {
            return;
        }
        let dir = match self.path.parent() {
            Some(d) => d,
            None => return,
        };
        let stem = match self.path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => return,
        };
        let prefix = format!("{stem}.");
        let mut archives: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| n.starts_with(&prefix))
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return,
        };
        // Names embed a zero-padded-by-magnitude unix-millis stamp; lexical
        // sort matches chronological order for all realistic timestamps.
        archives.sort();
        while archives.len() > self.max_archives {
            let oldest = archives.remove(0);
            if let Err(e) = std::fs::remove_file(&oldest) {
                tracing::warn!("audit archive prune failed for {}: {}", oldest.display(), e);
            }
        }
    }

    /// Bounded stream of the most recent `tail` records, oldest-first in the
    /// returned vectors.
    ///
    /// Keeps only the last `tail` records passing `keep` (and the last
    /// `tail` error-path records), so memory stays O(tail) no matter how
    /// large the log grows — the dashboard polls these endpoints every few
    /// seconds and must never re-materialize an unbounded file per request.
    /// Returns `(records, error_records, total_records, total_errors)` where
    /// the totals count every matching record / every error record in the
    /// log, so callers can report true volume without holding it in memory.
    ///
    /// Malformed lines (partial writes, corruption) are skipped defensively
    /// — the log is append-only, so a torn final line is possible and must
    /// never fail the read.
    ///
    /// Contract: memory is bounded by `tail` — at most `tail` matching
    /// records and at most `tail` error records are retained (`tail == 0`
    /// retains nothing). The returned totals count every matching record in
    /// the log, so they are exact without a sidecar counter. The read is a
    /// single forward scan, so time is O(log size) per call — fine for the
    /// dashboard's poll cadence on a single core node; an incremental index
    /// can make polls O(1) if the log ever outgrows a full scan.
    pub fn read_tail_filtered(
        &self,
        tail: usize,
        keep: impl Fn(&AuditRecord) -> bool,
    ) -> (Vec<AuditRecord>, Vec<AuditErrorRecord>, usize, usize) {
        let file = match File::open(self.path.as_ref()) {
            Ok(f) => f,
            Err(_) => return (Vec::new(), Vec::new(), 0, 0),
        };
        let mut records: std::collections::VecDeque<AuditRecord> = Default::default();
        let mut errors: std::collections::VecDeque<AuditErrorRecord> = Default::default();
        let mut total_records = 0usize;
        let mut total_errors = 0usize;
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditRecord>(&line) {
                Ok(r) => {
                    if keep(&r) {
                        total_records += 1;
                        if tail > 0 {
                            if records.len() == tail {
                                records.pop_front();
                            }
                            records.push_back(r);
                        }
                    }
                }
                Err(_) => {
                    if let Ok(e) = serde_json::from_str::<AuditErrorRecord>(&line) {
                        total_errors += 1;
                        if tail > 0 {
                            if errors.len() == tail {
                                errors.pop_front();
                            }
                            errors.push_back(e);
                        }
                    }
                    // else: malformed — skip (append-only log, torn tail)
                }
            }
        }
        (records.into(), errors.into(), total_records, total_errors)
    }

    /// Streaming per-program observation counts over the whole log.
    ///
    /// Memory is bounded by the number of distinct programs seen (never by
    /// log size) — used by `/api/protocols/top`.
    pub fn observations_by_program(&self) -> std::collections::HashMap<String, usize> {
        let file = match File::open(self.path.as_ref()) {
            Ok(f) => f,
            Err(_) => return std::collections::HashMap::new(),
        };
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(r) = serde_json::from_str::<AuditRecord>(&line) {
                *counts.entry(r.program_id).or_insert(0) += 1;
            }
            // Error records / malformed lines do not contribute observations.
        }
        counts
    }

    /// Append one record, flushing immediately so the line is durable before
    /// the HTTP response is sent. A write failure is logged, never fatal —
    /// verification must not fail because the audit disk is unavailable.
    pub fn append(&self, record: &AuditRecord) {
        self.append_line(record);
    }

    /// Append an error-path record (same durability contract).
    pub fn append_error(&self, record: &AuditErrorRecord) {
        self.append_line(record);
    }

    /// Append a lifecycle event (P9). Same durability contract as `append`:
    /// flushed before the caller is answered, non-fatal on failure but
    /// counted, and subject to the same rotation.
    pub fn append_lifecycle(&self, record: &LifecycleEventRecord) {
        self.append_line(record);
    }

    fn append_line<T: serde::Serialize>(&self, record: &T) {
        let line = match serde_json::to_string(record) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("audit serialization failed: {}", e);
                return;
            }
        };
        let mut file = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(e) = writeln!(file, "{}", line).and_then(|_| file.flush()) {
            // Non-fatal by design (a failing audit disk must not take down
            // verification) — but counted, so /health and /metrics can expose
            // it and an operator can alert instead of silently losing the
            // trail.
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
            tracing::error!("audit write failed: {}", e);
            return;
        }
        self.writes_ok.fetch_add(1, Ordering::Relaxed);
        // Rotate AFTER a successful append, while still holding the lock, so
        // the size check and rename cannot interleave with another writer.
        self.rotate_if_needed(&mut file);
    }
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
mod tests {
    use super::*;

    fn rec(id: &str) -> AuditRecord {
        AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: "2026-09-05T00:00:00.000Z".to_string(),
            audit_trail_id: id.to_string(),
            content_hash: "hash".to_string(),
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "system-program".to_string(),
            manifest_version: None,
            approved: true,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
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
            log.append(&rec(&format!("id-{i}")));
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
            log.append(&rec(&format!("id-{i}")));
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
            .map(|_| log.next_archive_path(FROZEN_STAMP))
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
            .map(|_| log.next_archive_path(FROZEN_STAMP))
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
            log.append(&rec(&format!("id-{i}")));
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
            log.append(&rec(&format!("id-{i}")));
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
            log.append(&rec(&format!("id-{i}")));
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
            log.append(&rec(&format!("id-{i}")));
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
            log.append(&rec(&format!("id-{i}")));
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
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "system-program".to_string(),
            manifest_version: None,
            approved: true,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
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
                log.append(&AuditRecord {
                    event_type: LifecycleEvent::Verification,
                    timestamp: format!("t{i}"),
                    audit_trail_id: format!("id{i}"),
                    content_hash: "h".into(),
                    program_id: if i % 2 == 0 {
                        "AAA".into()
                    } else {
                        "BBB".into()
                    },
                    instruction_name: "transfer".into(),
                    protocol_name: "system".into(),
                    manifest_version: None,
                    approved: i % 2 == 0,
                    confidence: 0.5,
                    risk_status: "Clear".into(),
                    policy_verdict: if i % 2 == 0 {
                        "Approved".into()
                    } else {
                        "Blocked".into()
                    },
                    l3_status: "inconclusive".into(),
                    l8_status: "inconclusive".into(),
                });
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
        let (records, errors, total, _) = log.read_tail_filtered(4, |r| r.approved);
        // 10 records, 5 approved; keep filter -> 5 approved, cap 4 -> last 4.
        assert_eq!(total, 5, "total must count all approved records");
        assert_eq!(records.len(), 4, "tail cap must bound the retained set");
        // Raw read is chronological (append order); the API layer reverses.
        // The 4 most recent approved by file position are i = 2, 4, 6, 8.
        let ids: Vec<&str> = records.iter().map(|r| r.audit_trail_id.as_str()).collect();
        assert_eq!(ids, vec!["id2", "id4", "id6", "id8"]);
        assert!(errors.is_empty(), "no error records written");

        // tail == 0 retains nothing but still reports exact totals.
        let (empty, _, zero_total, _) = log.read_tail_filtered(0, |_| true);
        assert!(empty.is_empty(), "tail 0 must retain nothing");
        assert_eq!(zero_total, 10, "totals stay exact under tail 0");

        // Error records are capped at tail too, and count toward total_errors.
        for i in 0..4 {
            log.append_error(&AuditErrorRecord {
                timestamp: format!("te{i}"),
                program_id: format!("prg{i}"),
                instruction_name: "transfer".into(),
                error: "bad payload".into(),
                error_type: "bad_input".into(),
                status: 400,
            });
        }
        let (_, errs, _, err_total) = log.read_tail_filtered(2, |_| true);
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
}
