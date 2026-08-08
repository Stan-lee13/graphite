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
use std::sync::{Arc, Mutex};

/// Append-only audit log of verification results.
///
/// `Clone` shares the same underlying file (used inside axum State).
#[derive(Debug, Clone)]
pub struct AuditLog {
    file: std::sync::Arc<Mutex<File>>,
    /// The log's path, kept so the read path (`read_all`) can re-open the
    /// file for reading without disturbing the append handle.
    path: Arc<PathBuf>,
}

/// A minimal, self-contained record of a verification outcome. Deliberately
/// excludes the raw account list / instruction payload — the deterministic
/// `content_hash` and `audit_trail_id` are the linkage keys for any deeper
/// forensic lookup (Constitution P4/P5: enough to reproduce, not to leak).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
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
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file: std::sync::Arc::new(Mutex::new(file)),
            path: Arc::new(path),
        })
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
            tracing::error!("audit write failed: {}", e);
        }
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

    /// GAP-2026-08-06-3: the audit record must carry the REAL L3/L8 layer
    /// states (never the old phantom `passed: true`).
    #[test]
    fn audit_record_serializes_l3_and_l8_status() {
        let record = AuditRecord {
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
