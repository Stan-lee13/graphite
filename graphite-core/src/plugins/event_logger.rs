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
/// sequential under a mutex; failures (disk full, permissions) are returned
/// to the logger, which logs and continues.
pub struct FileSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileSink {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            lock: Mutex::new(()),
        }
    }
}

impl EventSink for FileSink {
    fn write_event(&self, event: &VerificationEvent) -> Result<(), String> {
        let line = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        writeln!(f, "{}", line).map_err(|e| e.to_string())
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
        let sinks = self.sinks.lock().unwrap_or_else(|p| p.into_inner());
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
            approved,
            confidence: 0.7,
            breakdown: vec![],
            trust_tier: "OfficialManifest".to_string(),
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
            transaction: crate::transaction_builder::BuiltTransaction {
                program_id: "11111111111111111111111111111111".to_string(),
                protocol_version: "1.0.0".to_string(),
                instruction_name: "Transfer".to_string(),
                instruction_discriminator: "02000000".to_string(),
                instruction_count: 1,
                account_count: 2,
                signer_count: 1,
                writable_count: 1,
                compute_budget_units: 0,
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

    #[test]
    fn test_event_carries_layer_statuses() {
        let ring = RingBufferSink::new(8);
        let plugin = VerificationEventLoggerPlugin::with_sinks(vec![Arc::new(ring)]);
        plugin.on_verification(&fake_result(true));
        let events = plugin.buffered_events();
        assert_eq!(events[0].layers, vec!["L2_InstructionVerification=passed"]);
    }
}
