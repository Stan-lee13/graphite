//! The verification event logger — a strictly read-only AnalyticsPlugin.
//!
//! Observes every completed verification result and writes a compact,
//! DETERMINISTIC `VerificationEvent` to registered `EventSink`s. It never
//! writes back into the Semantic Graph, the audit trail, or the registry
//! (P8: analytics plugins are read-only observers) — and sink failures are
//! logged, never fatal (observability must not break verification).
//!
//! Determinism note: `VerificationEvent` deliberately carries no wall-clock
//! timestamp — the event content is a pure function of the verification
//! result, so identical inputs produce byte-identical events (P2). Consumers
//! that need ingestion time add it at the sink edge.

use crate::plugin_orchestrator::{AnalyticsPlugin, LayerId, PluginManifest, ReviewStatus};
use crate::verification::VerificationResult;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// First-party plugin name (discovery key for manifest-driven activation).
pub const NAME: &str = "verification-event-logger";

/// Default ring-buffer capacity when no sink is configured.
const DEFAULT_RING_CAPACITY: usize = 1024;

/// A compact, deterministic record of one completed verification.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct VerificationEvent {
    pub audit_trail_id: String,
    pub content_hash: String,
    pub program_id: String,
    pub protocol_name: String,
    pub instruction_name: String,
    pub instruction_discriminator: String,
    pub approved: bool,
    pub confidence: f64,
    pub trust_tier: String,
    pub risk_status: String,
    pub policy_verdict: String,
    pub manifest_found: bool,
    pub unknown_protocol: bool,
    /// `"L2_InstructionVerification=passed"`-style pairs, in pipeline order.
    pub layers: Vec<String>,
}

impl VerificationEvent {
    pub fn from_result(r: &VerificationResult) -> Self {
        Self {
            audit_trail_id: r.audit_trail_id.clone(),
            content_hash: r.content_hash.clone(),
            program_id: r.transaction.program_id.clone(),
            protocol_name: r.protocol_name.clone(),
            instruction_name: r.instruction_name.clone(),
            instruction_discriminator: r.transaction.instruction_discriminator.clone(),
            approved: r.approved,
            confidence: r.confidence,
            trust_tier: r.trust_tier.clone(),
            risk_status: r.risk_verdict.status.clone(),
            policy_verdict: r.policy_verdict.clone(),
            manifest_found: r.manifest_found,
            unknown_protocol: r.unknown_protocol,
            layers: r
                .layers
                .iter()
                .map(|l| format!("{}={}", l.layer, l.status.as_str()))
                .collect(),
        }
    }
}

/// A destination for verification events. Failures are returned as `Err` and
/// logged by the logger — a sink must never be able to break verification.
pub trait EventSink: Send + Sync {
    fn write_event(&self, event: &VerificationEvent) -> Result<(), String>;

    /// Downcast support for the read-side API (e.g. snapshotting ring-buffer
    /// sinks). Implementors return `self`.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// In-memory bounded ring buffer. Evicts oldest events beyond capacity, so a
/// long-running process has bounded memory regardless of verification volume.
pub struct RingBufferSink {
    capacity: usize,
    events: Mutex<VecDeque<VerificationEvent>>,
}

impl RingBufferSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.clamp(1, 1 << 20),
            events: Mutex::new(VecDeque::with_capacity(capacity.clamp(1, 1 << 20))),
        }
    }

    /// Snapshot of the current buffered events (oldest first).
    pub fn snapshot(&self) -> Vec<VerificationEvent> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl EventSink for RingBufferSink {
    fn write_event(&self, event: &VerificationEvent) -> Result<(), String> {
        let mut q = self.events.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() == self.capacity {
            q.pop_front();
        }
        q.push_back(event.clone());
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Append-only JSON-lines file sink. Each event is one line. Writes are
/// sequential under the sink's own mutex; failures (disk full, permissions)
/// are returned to the logger, which logs and continues.
///
/// Round 29 (audit 2026-10-20, P-2): the file is opened once and kept open,
/// and reopened only after a failure (or on [`FileSink::reopen`], e.g. after
/// an operator rotates the file). It was opened and closed for every event,
/// under the logger's global sinks lock — a filesystem round trip per
/// verification, serialised across every verification in the process. Each
/// line is one `write_all` of the event plus its newline, so a failure never
/// leaves half an event followed by the next one on the same line.
pub struct FileSink {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
}

impl FileSink {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Mutex::new(None),
        }
    }

    /// Close the file; the next event reopens it at `path` (append). For an
    /// operator who rotated or removed the file: the open handle would
    /// otherwise keep writing to the old one.
    pub fn reopen(&self) {
        *self.file.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

impl EventSink for FileSink {
    fn write_event(&self, event: &VerificationEvent) -> Result<(), String> {
        let mut line = serde_json::to_string(event).map_err(|e| e.to_string())?;
        line.push('\n');
        use std::io::Write;
        let mut slot = self.file.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                    .map_err(|e| e.to_string())?,
            );
        }
        let result = slot
            .as_mut()
            .map(|f| f.write_all(line.as_bytes()))
            .unwrap_or(Ok(()));
        if let Err(e) = result {
            // A handle that failed once is not trusted again: the next event
            // opens the file afresh.
            *slot = None;
            return Err(e.to_string());
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The built-in analytics plugin: fans each verification event out to its
/// registered sinks. Sinks are stored behind a `Mutex<Vec<..>>` so a file sink
/// can be attached after registration (e.g. server startup configuration)
/// while remaining shared across `GraphiteCore` clones.
pub struct VerificationEventLoggerPlugin {
    manifest: PluginManifest,
    sinks: Mutex<Vec<Arc<dyn EventSink>>>,
}

impl VerificationEventLoggerPlugin {
    pub fn new() -> Self {
        Self {
            manifest: PluginManifest {
                name: NAME.to_string(),
                version: "1.0.0".to_string(),
                author: "graphite-core".to_string(),
                layer: LayerId::L8ExecutionVerification,
                review_status: ReviewStatus::Approved,
                description: "Read-only analytics: records every verification result to configured event sinks (ring buffer, file)".to_string(),
            },
            sinks: Mutex::new(vec![Arc::new(RingBufferSink::new(DEFAULT_RING_CAPACITY))]),
        }
    }

    /// Construct with explicit sinks (e.g. a file sink for production).
    pub fn with_sinks(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self {
            manifest: PluginManifest {
                name: NAME.to_string(),
                version: "1.0.0".to_string(),
                author: "graphite-core".to_string(),
                layer: LayerId::L8ExecutionVerification,
                review_status: ReviewStatus::Approved,
                description: "Read-only analytics: records every verification result to configured event sinks (ring buffer, file)".to_string(),
            },
            sinks: Mutex::new(sinks),
        }
    }

    /// Attach another sink after construction (thread-safe, shared across
    /// `GraphiteCore` clones).
    pub fn add_sink(&self, sink: Arc<dyn EventSink>) {
        self.sinks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(sink);
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// All events currently buffered across ring-buffer sinks, oldest first.
    pub fn buffered_events(&self) -> Vec<VerificationEvent> {
        let mut out = Vec::new();
        for sink in self.sinks.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            if let Some(ring) = sink_as_ring(sink) {
                out.extend(ring.snapshot());
            }
        }
        out
    }
}

impl Default for VerificationEventLoggerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyticsPlugin for VerificationEventLoggerPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn on_verification(&self, result: &VerificationResult) {
        let event = VerificationEvent::from_result(result);
        // P-2 (Round 29): the sinks lock guards the LIST, and is held only
        // to copy it. Holding it across every sink's I/O made each
        // verification wait for every other's file write; each sink now
        // serialises its own writes, and only those.
        let sinks: Vec<Arc<dyn EventSink>> =
            self.sinks.lock().unwrap_or_else(|p| p.into_inner()).clone();
        for sink in sinks.iter() {
            if let Err(e) = sink.write_event(&event) {
                tracing::warn!("event sink failed (verification result unaffected): {}", e);
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Downcast a trait object to a concrete `RingBufferSink` (used by the
/// read-side test/observability API). Sound: `as_any` is a required trait
/// method, so every `EventSink` impl provides a real bridge.
fn sink_as_ring(sink: &Arc<dyn EventSink>) -> Option<&RingBufferSink> {
    sink.as_any().downcast_ref::<RingBufferSink>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{LayerStatus, PipelineLayerResult, RiskVerdictSummary};

    fn fake_result(approved: bool) -> VerificationResult {
        VerificationResult {
            program_upgrades: Vec::new(),
            approved,
            decision: if approved {
                crate::verification::ExecutionDecision::AnalysisOnly
            } else {
                crate::verification::ExecutionDecision::Blocked
            },
            executable: false,
            confidence: 0.7,
            breakdown: vec![],
            trust_tier: "OfficialManifest".to_string(),
            scope: crate::verification::VerificationScope::Descriptive {
                unobserved: vec!["test fixture; no transaction was supplied".to_string()],
                unobserved_codes: vec![crate::verification::UnobservedCode::NoArtifact],
            },
            risk_verdict: RiskVerdictSummary {
                status: if approved {
                    "Clear".into()
                } else {
                    "Blocked".into()
                },
                findings: vec![],
            },
            policy_verdict: if approved {
                "Approved".into()
            } else {
                "Rejected".into()
            },
            audit_trail_id: "gr-abc".to_string(),
            content_hash: "hash-abc".to_string(),
            instruction_bind_key: "hash-abc".to_string(),
            transaction: crate::transaction_builder::InstructionSummary {
                program_id: "11111111111111111111111111111111".to_string(),
                protocol_version: "1.0.0".to_string(),
                instruction_name: "Transfer".to_string(),
                instruction_discriminator: "02000000".to_string(),
                instruction_count: 1,
                account_count: 2,
                signer_count: 1,
                writable_count: 1,
                compute_units_estimate: 0,
                accounts: vec![],
                data_hex: "".to_string(),
                data_len: 0,
            },
            resolved_accounts: vec![],
            protocol_name: "System Program".to_string(),
            instruction_name: "Transfer".to_string(),
            manifest_found: true,
            unknown_protocol: false,
            manifest_version: Some("1.0.0".to_string()),
            summary: "s".to_string(),
            simulation_flagged: None,
            simulation_divergence: None,
            layers: vec![PipelineLayerResult::new(
                "L2_InstructionVerification",
                LayerStatus::Passed,
                "ok",
            )],
        }
    }

    #[test]
    fn test_ring_buffer_bounded_memory() {
        let ring = RingBufferSink::new(4);
        let plugin = VerificationEventLoggerPlugin::with_sinks(vec![Arc::new(ring)]);
        for _ in 0..100 {
            plugin.on_verification(&fake_result(true));
        }
        // Bounded: only the newest 4 survive; the first event is evicted.
        let events = plugin.buffered_events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].audit_trail_id, "gr-abc");
    }

    #[test]
    fn test_event_is_deterministic() {
        let ring = RingBufferSink::new(16);
        let plugin = VerificationEventLoggerPlugin::with_sinks(vec![Arc::new(ring)]);
        let r = fake_result(true);
        plugin.on_verification(&r);
        plugin.on_verification(&r);
        let events = plugin.buffered_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], events[1]);
    }

    #[test]
    fn test_file_sink_appends_jsonl() {
        let dir = std::env::temp_dir().join(format!("graphite-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let plugin =
            VerificationEventLoggerPlugin::with_sinks(vec![Arc::new(FileSink::new(&path))]);
        plugin.on_verification(&fake_result(true));
        plugin.on_verification(&fake_result(false));
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line parses as a VerificationEvent-shaped JSON object.
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["audit_trail_id"], "gr-abc");
        assert_eq!(v["approved"], true);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_sink_error_is_non_fatal() {
        // Writing to a path whose parent does not exist returns Err — the
        // logger logs it and verification is unaffected (no panic).
        let plugin = VerificationEventLoggerPlugin::with_sinks(vec![Arc::new(FileSink::new(
            Path::new("/definitely/not/a/real/dir/events.jsonl"),
        ))]);
        plugin.on_verification(&fake_result(true)); // must not panic
    }

    /// Round 29 (P-2): the logger's sinks lock is not held while a sink does
    /// its I/O.
    #[test]
    fn the_sinks_lock_is_not_held_during_sink_io() {
        struct Probe {
            logger: std::sync::OnceLock<std::sync::Weak<VerificationEventLoggerPlugin>>,
            lock_was_free: std::sync::atomic::AtomicBool,
        }
        impl EventSink for Probe {
            fn write_event(&self, _: &VerificationEvent) -> Result<(), String> {
                let logger = self.logger.get().and_then(|w| w.upgrade()).unwrap();
                let free = logger.sinks.try_lock().is_ok();
                self.lock_was_free
                    .store(free, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        let probe = Arc::new(Probe {
            logger: std::sync::OnceLock::new(),
            lock_was_free: std::sync::atomic::AtomicBool::new(false),
        });
        let plugin = Arc::new(VerificationEventLoggerPlugin::with_sinks(vec![
            probe.clone()
        ]));
        probe.logger.set(Arc::downgrade(&plugin)).ok().unwrap();
        plugin.on_verification(&fake_result(true));
        assert!(probe
            .lock_was_free
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Round 29 (P-2): the file sink keeps its file open, and `reopen` (or a
    /// failed write) makes the next event open the path afresh.
    #[test]
    fn the_file_sink_keeps_its_file_and_reopens_on_request() {
        let dir =
            std::env::temp_dir().join(format!("graphite-events-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let sink = FileSink::new(&path);
        let event = VerificationEvent::from_result(&fake_result(true));
        sink.write_event(&event).unwrap();
        assert!(sink.file.lock().unwrap().is_some(), "kept open");
        // Rotated away: the open handle writes to the moved file until reopened.
        let rotated = dir.join("events.jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        sink.write_event(&event).unwrap();
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap().lines().count(),
            2
        );
        sink.reopen();
        sink.write_event(&event).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_event_carries_layer_statuses() {
        let ring = RingBufferSink::new(8);
        let plugin = VerificationEventLoggerPlugin::with_sinks(vec![Arc::new(ring)]);
        plugin.on_verification(&fake_result(true));
        let events = plugin.buffered_events();
        assert_eq!(events[0].layers, vec!["L2_InstructionVerification=passed"]);
    }
}
