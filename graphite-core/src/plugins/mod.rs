//! Built-in first-party plugins (security-reviewed in-tree).
//!
//! These ship registered on `GraphiteCore::new()` and are the reference
//! implementations of the plugin contract. Third-party plugins activate only
//! through the manifest review gate (see `plugin_orchestrator.rs`).

pub mod event_logger;
pub mod fake_rewards_drainer;

pub use event_logger::{
    EventSink, FileSink, RingBufferSink, VerificationEvent, VerificationEventLoggerPlugin,
};
pub use fake_rewards_drainer::FakeRewardsDrainerRiskPlugin;

use crate::plugin_orchestrator::PluginKind;

/// Names of the built-in plugins (the discovery keys used by manifests).
pub const FAKE_REWARDS_DRAINER_NAME: &str = "fake-rewards-drainer";
pub const VERIFICATION_EVENT_LOGGER_NAME: &str = "verification-event-logger";

/// Resolve a built-in plugin by its manifest name (review gate: only these
/// names may activate from an approved manifest).
pub fn builtin_plugin(name: &str) -> Option<PluginKind> {
    match name {
        FAKE_REWARDS_DRAINER_NAME => Some(PluginKind::Risk(std::sync::Arc::new(
            FakeRewardsDrainerRiskPlugin::new(),
        ))),
        VERIFICATION_EVENT_LOGGER_NAME => Some(PluginKind::Analytics(std::sync::Arc::new(
            VerificationEventLoggerPlugin::new(),
        ))),
        _ => None,
    }
}

/// The full built-in plugin set (registered on `GraphiteCore::new()`).
pub fn builtin_plugins() -> Vec<PluginKind> {
    vec![
        builtin_plugin(FAKE_REWARDS_DRAINER_NAME).expect("builtin exists"),
        builtin_plugin(VERIFICATION_EVENT_LOGGER_NAME).expect("builtin exists"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_names_resolve() {
        assert!(builtin_plugin(FAKE_REWARDS_DRAINER_NAME).is_some());
        assert!(builtin_plugin(VERIFICATION_EVENT_LOGGER_NAME).is_some());
        assert!(builtin_plugin("unknown").is_none());
    }

    #[test]
    fn test_builtin_manifest_fields() {
        for kind in builtin_plugins() {
            let m = kind.manifest();
            assert!(!m.name.is_empty());
            assert!(!m.version.is_empty());
            assert!(!m.author.is_empty());
            assert_eq!(
                m.review_status,
                crate::plugin_orchestrator::ReviewStatus::Approved
            );
        }
    }
}
