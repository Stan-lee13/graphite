//! Durability — audit trail persistence for verification results.
//!
//! The semantic-graph/baseline snapshot is handled inside
//! [`crate::verification::GraphiteCore::with_data_dir`]; this module owns the
//! append-only JSONL audit log that the HTTP server writes after every
//! verification. One JSON object per line, flushed per write so a crash loses
//! at most the in-flight request.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Append-only audit log of verification results.
///
/// `Clone` shares the same underlying file (used inside axum State).
#[derive(Debug, Clone)]
pub struct AuditLog {
    file: std::sync::Arc<Mutex<File>>,
}

/// A minimal, self-contained record of a verification outcome. Deliberately
/// excludes the raw account list / instruction payload — the deterministic
/// `content_hash` and `audit_trail_id` are the linkage keys for any deeper
/// forensic lookup (Constitution P4/P5: enough to reproduce, not to leak).
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone, serde::Serialize)]
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
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: std::sync::Arc::new(Mutex::new(file)),
        })
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
}
