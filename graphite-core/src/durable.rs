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
    by_program: HashMap<String, usize>,
}

impl ArchiveStats {
    fn records(&self, selector: AuditSelector) -> usize {
        match selector {
            AuditSelector::All => self.approved + self.blocked,
            AuditSelector::Approved => self.approved,
            AuditSelector::Blocked => self.blocked,
        }
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

fn scan_file(file: File, len: u64, tail: usize, selector: AuditSelector) -> FileScan {
    let mut stats = ArchiveStats {
        len,
        ..Default::default()
    };
    let mut records: VecDeque<AuditRecord> = VecDeque::new();
    let mut errors: VecDeque<AuditErrorRecord> = VecDeque::new();
    // Streamed, one line at a time: an archive can be 64 MiB.
    for_each_line(file, |line| {
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

/// Make a directory entry change (a rename, a newly created file) durable.
///
/// On Unix the rename that rotation performs lives in the directory, and the
/// directory has its own write-back cache; without this a power loss after
/// rotation can leave the archive name unlinked while the data survives. On
/// Windows `MoveFileEx` is journaled by NTFS and directories cannot be
/// opened for sync, so this is a no-op there.
fn sync_dir(path: &Path) {
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
    /// An operator changed the gate's own state — today, withdrawing a program
    /// from trust or restoring it.
    ///
    /// Self-observed: Graphite performs the action itself, so a caller must not
    /// be able to report one. Otherwise anyone could write "quarantine lifted
    /// for X" into the audit trail without a quarantine ever being lifted,
    /// which is exactly the forged history `is_self_observed` exists to stop.
    /// `content_hash` carries the program id rather than a transaction hash —
    /// this event is about a program, not a transaction.
    OperatorAction,
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
                | LifecycleEvent::OperatorAction
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
const MAX_AUDIT_FIELD_CHARS: usize = 256;

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

/// One pass over the active file: the offset of the last verification line
/// per key, and the offsets of every lifecycle row per transaction key. A
/// torn final line and an error record are neither and are skipped.
fn build_indexes(path: &Path) -> (HashMap<String, u64>, HashMap<String, Vec<u64>>) {
    let mut index = HashMap::new();
    let mut lifecycle = HashMap::new();
    let Ok(file) = File::open(path) else {
        return (index, lifecycle);
    };
    let mut reader = BufReader::new(file);
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
            for k in index_keys(&r) {
                index.insert(k, offset);
            }
        } else if let Some(r) = lifecycle_row(&line) {
            for k in r.lifecycle_keys() {
                push_lifecycle_offset(&mut lifecycle, k, offset);
            }
        }
        offset += n as u64;
    }
    (index, lifecycle)
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
        let (active_index, lifecycle_index) = build_indexes(&path);
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
            rotate_bytes,
            max_archives,
            writes_ok: Arc::new(AtomicU64::new(0)),
            writes_failed: Arc::new(AtomicU64::new(0)),
            rotation_seq: Arc::new(AtomicU64::new(0)),
            rotations_ok: Arc::new(AtomicU64::new(0)),
            rotations_failed: Arc::new(AtomicU64::new(0)),
            archive_stats: Arc::new(Mutex::new(HashMap::new())),
            active_index: Arc::new(Mutex::new(active_index)),
            lifecycle_index: Arc::new(Mutex::new(lifecycle_index)),
            // A freshly opened log may sit beside an archive written by the
            // process that just exited; treat open as a rotation so that
            // archive is consulted for the first window.
            last_rotation: Arc::new(Mutex::new(Some(std::time::Instant::now()))),
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
            rotations_ok: self.rotations_ok.load(Ordering::Relaxed),
            rotations_failed: self.rotations_failed.load(Ordering::Relaxed),
            archive_count: self.archives().len() as u64,
        }
    }

    /// Every rotated archive on disk, oldest first.
    ///
    /// Names embed a fixed-width unix-millis stamp and a zero-padded sequence,
    /// so lexical order is chronological order — the same invariant
    /// `prune_archives` relies on to remove the oldest.
    fn archives(&self) -> Vec<PathBuf> {
        let Some(dir) = self.path.parent() else {
            return Vec::new();
        };
        let Some(stem) = self.path.file_name().and_then(|s| s.to_str()) else {
            return Vec::new();
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
            Err(_) => return Vec::new(),
        };
        archives.sort();
        archives
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
        let active = File::open(self.path.as_ref())
            .ok()
            .and_then(|f| f.metadata().ok().map(|m| (f, m.len())));
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
        let scan = scan_file(file, len, tail, selector);
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

        // If the rename fails (permissions, cross-device, another process
        // holding the file without delete-sharing), keep appending to the
        // current file rather than losing the record — an oversized log is
        // strictly better than a dropped audit trail. It is retried on the
        // next append and COUNTED, so /health shows a log that cannot rotate
        // instead of one that merely looks large.
        //
        // The rename happens with our own append handle still open. That is
        // fine on every platform Rust's std supports: on Unix a rename never
        // cares about open descriptors, and on Windows `OpenOptions` opens
        // with `FILE_SHARE_DELETE`, under which `MoveFileEx` succeeds on an
        // open file (verified by `active_audit_file_is_bounded_by_rotation`
        // running on NTFS). What breaks it is a FOREIGN handle without that
        // share mode — `rotation_failure_is_counted_and_never_drops_a_record`
        // reproduces exactly that.
        if let Err(e) = std::fs::rename(self.path.as_ref(), &archive) {
            let n = self.rotations_failed.fetch_add(1, Ordering::Relaxed) + 1;
            // Once per failure would page on every append; log the first and
            // then every 1000th so the condition stays visible without
            // flooding.
            if n == 1 || n.is_multiple_of(1000) {
                tracing::error!(
                    "audit rotation failed ({n} times): {e}; the active file keeps growing"
                );
            }
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.as_ref())
        {
            Ok(fresh) => {
                *file = fresh;
                // The active file is empty now; every offset the index
                // holds points into the archive.
                match self.active_index.lock() {
                    Ok(mut g) => g.clear(),
                    Err(poisoned) => poisoned.into_inner().clear(),
                }
                match self.lifecycle_index.lock() {
                    Ok(mut g) => g.clear(),
                    Err(poisoned) => poisoned.into_inner().clear(),
                }
                match self.last_rotation.lock() {
                    Ok(mut g) => *g = Some(std::time::Instant::now()),
                    Err(poisoned) => *poisoned.into_inner() = Some(std::time::Instant::now()),
                }
                // The rename and the new file are directory entries; make
                // them durable so a crash right after rotation cannot lose
                // the archive's NAME while its data survives.
                sync_dir(self.path.as_ref());
                self.rotations_ok.fetch_add(1, Ordering::Relaxed);
                tracing::info!("audit log rotated to {}", archive.display());
                self.prune_archives();
            }
            Err(e) => {
                // We already renamed the old file away; try to restore it so
                // no window exists with no audit file at all.
                let _ = std::fs::rename(&archive, self.path.as_ref());
                self.rotations_failed.fetch_add(1, Ordering::Relaxed);
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
        let mut archives = self.archives();
        while archives.len() > self.max_archives {
            let oldest = archives.remove(0);
            if let Err(e) = std::fs::remove_file(&oldest) {
                tracing::warn!("audit archive prune failed for {}: {}", oldest.display(), e);
            }
        }
        self.forget_missing_archives(&archives);
    }

    /// The most recent `tail` records the selector keeps, oldest-first, from
    /// the WHOLE trail: every rotated archive and the active file.
    ///
    /// Returns `(records, error_records, total_records, total_errors)`. The
    /// totals are exact over the whole trail. Memory is bounded by `tail`
    /// plus one archive's per-program statistics; it never depends on how
    /// large the trail has grown. `tail == 0` retains nothing and still
    /// reports exact totals.
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

    /// The most recent verification record under `key`, from the whole
    /// trail — the active file by index, then the archives newest-first.
    ///
    /// `AuditTrailId` is exact (one verification). `TransactionSha256` is
    /// exact about the bytes and newest-first about the decision, which is
    /// the decision that governed at submission. `ContentHash` is the
    /// instruction-level key and answers for whichever transaction carrying
    /// that instruction was verified last; callers that have a better key
    /// must use it (Round 10).
    /// How many verifications the trail holds for `key`, split by verdict:
    /// `(approved, refused)`. Whole trail — active file and every archive.
    ///
    /// Round 17 (F-16-11): `find_verification` answers with the LAST record
    /// for a key, so the same artifact refused once and approved later
    /// reconciled as approved with no sign that a refusal existed. L8 now
    /// reports these counts beside the record it resolved.
    pub fn count_verifications(&self, key: VerificationKey<'_>) -> (usize, usize) {
        let wanted = key.value().trim();
        if wanted.is_empty() {
            return (0, 0);
        }
        let mut approved = 0usize;
        let mut refused = 0usize;
        let mut tally = |file: File| {
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
        };
        let archives = {
            let _guard = match self.file.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Ok(file) = File::open(self.path.as_ref()) {
                tally(file);
            }
            self.archives()
        };
        for archive in archives {
            if let Ok(file) = File::open(archive) {
                tally(file);
            }
        }
        (approved, refused)
    }

    pub fn find_verification(&self, key: VerificationKey<'_>) -> Option<AuditRecord> {
        let wanted = key.value().trim();
        if wanted.is_empty() {
            return None;
        }
        let index_key = key.index_key();
        let find_in = |file: File| -> Option<AuditRecord> {
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
                if let Some(r) = File::open(self.path.as_ref()).ok().and_then(find_in) {
                    return Some(r);
                }
            }
            self.archives()
        };
        // Not in the active file. The archives are immutable and searched
        // newest-first.
        for archive in archives.iter().rev() {
            if let Ok(file) = File::open(archive) {
                if let Some(r) = find_in(file) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Per-program observation counts over the whole trail.
    ///
    /// Memory is bounded by the number of distinct programs seen (never by
    /// trail size) — used by `/api/protocols/top`. Archives contribute from
    /// the cache after their first scan.
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
        self.append_line_indexed(record, &index_keys(record))
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
        self.append_line_with(&bounded, &[], &keys)
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
        self.append_line_with(record, &[], &[])
    }

    /// `append_line`, recording every entry of `index_keys` → this line's
    /// offset in the active index when the write succeeds. The offset is the
    /// file's length before the write, read under the same lock the write
    /// holds, so no other writer can interleave between the two.
    fn append_line_indexed<T: serde::Serialize>(&self, record: &T, index_keys: &[String]) -> bool {
        self.append_line_with(record, index_keys, &[])
    }

    /// `append_line_indexed` with the lifecycle keys this line is indexed
    /// under as well (Round 12).
    fn append_line_with<T: serde::Serialize>(
        &self,
        record: &T,
        index_keys: &[String],
        lifecycle_keys: &[String],
    ) -> bool {
        let line = match serde_json::to_string(record) {
            Ok(l) => l,
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
        if self.torn_tail.load(Ordering::SeqCst) {
            if let Err(e) = file.write_all(b"\n").and_then(|_| file.sync_data()) {
                self.writes_failed.fetch_add(1, Ordering::Relaxed);
                tracing::error!("audit write failed (terminating a partial line): {}", e);
                return false;
            }
            self.torn_tail.store(false, Ordering::SeqCst);
        }
        let offset = if index_keys.is_empty() && lifecycle_keys.is_empty() {
            None
        } else {
            file.metadata().ok().map(|m| m.len())
        };
        if let Err(e) = writeln!(file, "{}", line).and_then(|_| file.sync_data()) {
            // Part of the line may have landed.
            self.torn_tail.store(true, Ordering::SeqCst);
            // Counted AND reported. The comment here used to say a failing
            // audit disk "must not take down verification", and that reasoning
            // is right for the process — the server should stay up — but wrong
            // for the individual answer. A verdict Graphite cannot record is a
            // verdict it should not hand back as though it had.
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
            tracing::error!("audit write failed: {}", e);
            return false;
        }
        self.writes_ok.fetch_add(1, Ordering::Relaxed);
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
fn for_each_line(file: File, mut visit: impl FnMut(&str)) {
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
                    confidence: 0.5,
                    risk_status: "Clear".into(),
                    policy_verdict: if i % 2 == 0 {
                        "Approved".into()
                    } else {
                        "Blocked".into()
                    },
                    l3_status: "inconclusive".into(),
                    l8_status: "inconclusive".into(),
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

        // Pruning drops the entry.
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

    /// The Unix twin: a directory the process cannot rename inside.
    #[cfg(unix)]
    #[test]
    fn rotation_failure_is_counted_and_never_drops_a_record() {
        use std::os::unix::fs::PermissionsExt;
        // Root ignores directory permissions; the test is meaningless there.
        if unsafe { libc_geteuid() } == 0 {
            eprintln!("skipping: running as root, directory permissions do not apply");
            return;
        }
        let dir = temp_dir("readonly-dir");
        let log = AuditLog::open_with_rotation(audit_path(&dir), 512, 0).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
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

    #[cfg(unix)]
    extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
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
    /// file. Measurement, reported; the assertion is only that the substring
    /// prefilter keeps a miss on a 64 MB trail under a second, since a miss
    /// (a hash with no verification on record) is the case a caller can
    /// force at will.
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
        // A record appended after open is found through the index too, and
        // the newest one wins.
        assert!(log.append(&rec_with("gr-new", "0000000000000010", "P", false)));
        let newest = log.last_verification_for("0000000000000010").unwrap();
        assert_eq!(newest.audit_trail_id, "gr-new");
        assert!(!newest.approved);
        println!(
            "round9: last_verification_for over a {} MB active file: full scan {:?}; indexed: open {:?}, hit {:?}, miss {:?}",
            len / (1024 * 1024),
            full_scan,
            open_cost,
            hit_cost,
            miss_cost
        );
        assert!(
            hit_cost.as_millis() < 50 && miss_cost.as_millis() < 50,
            "an indexed lookup must not scan the file: hit {hit_cost:?}, miss {miss_cost:?}"
        );
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
        // Poison the index: point the hash at a wrong offset. The lookup
        // must fall back to a scan and still find the right record.
        log.active_index
            .lock()
            .unwrap()
            .insert("aaaaaaaaaaaaaaaa".to_string(), 7);
        let r = log.last_verification_for("aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(r.audit_trail_id, "gr-a");
        assert!(r.approved);
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
        drop(log);
        let reopened = AuditLog::open_with_rotation(&path, 2_000, 0).unwrap();
        for i in 0..20 {
            assert!(reopened
                .last_verification_for(&format!("{i:016x}"))
                .is_some());
        }
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
}
