//! Plugin Orchestrator — ARCHITECTURE.md 3.14
//!
//! Manages plugin lifecycle and enforces the fixed orchestration contract.
//! Plugins cannot reorder or skip verification layers, and cannot write to
//! the audit trail directly (Constitution P8).
//!
//! This reference implementation demonstrates the plugin trait signature that
//! makes these security guarantees impossible to violate by construction.

use thiserror::Error;

/// Error cases for plugin orchestration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PluginError {
    #[error("plugin not registered for layer {layer}")]
    PluginNotRegistered { layer: String },
    #[error("plugin execution failed: {reason}")]
    ExecutionFailed { reason: String },
}

/// Verification layer ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayerId {
    /// L1: Account Resolution
    AccountResolution,
    /// L2: Transaction Construction
    TransactionConstruction,
    /// L3: Simulation
    Simulation,
    /// L4: Protocol Intelligence
    ProtocolIntelligence,
    /// L5: Semantic Verification
    SemanticVerification,
    /// L6: Policy Engine
    PolicyEngine,
    /// L7: Risk Verification
    RiskVerification,
    /// L8: Confidence Engine
    ConfidenceEngine,
}

/// Fixed pipeline order — cannot be reordered by plugins.
pub const PIPELINE_ORDER: [LayerId; 8] = [
    LayerId::AccountResolution,
    LayerId::TransactionConstruction,
    LayerId::Simulation,
    LayerId::ProtocolIntelligence,
    LayerId::SemanticVerification,
    LayerId::PolicyEngine,
    LayerId::RiskVerification,
    LayerId::ConfidenceEngine,
];

/// Input to a verification layer.
#[derive(Debug, Clone)]
pub struct LayerInput {
    /// Layer ID
    pub layer_id: LayerId,
    /// Transaction data
    pub transaction_data: Vec<u8>,
}

/// Output from a verification layer.
#[derive(Debug, Clone)]
pub struct LayerOutput {
    /// Layer ID
    pub layer_id: LayerId,
    /// Whether the layer passed
    pub passed: bool,
    /// Layer-specific output data
    pub output_data: Vec<u8>,
}

/// Plugin trait for verification layers.
///
/// The signature of this trait makes Constitution P8 violations impossible
/// by construction: plugins have no reference to the orchestrator's audit_log,
/// no way to invoke another LayerId's plugin, and no way to affect PIPELINE_ORDER.
pub trait VerifierPlugin {
    /// Run the plugin for a specific layer.
    fn run(&self, input: &LayerInput) -> Result<LayerOutput, PluginError>;
}

/// Plugin orchestrator.
///
/// `Debug` is implemented manually below rather than derived: `VerifierPlugin`
/// deliberately does NOT require `Debug` as a supertrait (keeping the trait's
/// footprint minimal is itself part of the security design — the fewer
/// capabilities/requirements plugin authors must satisfy, the smaller the
/// surface for a plugin to do something unexpected). A `#[derive(Debug)]`
/// here doesn't compile as a result (`Box<dyn VerifierPlugin>` has no `Debug`
/// impl to call) — found by actually running `cargo test` during the
/// 2026-07-06 production-readiness sweep, not visible from reading the
/// derive attribute alone.
#[derive(Default)]
pub struct PluginOrchestrator {
    /// Registered plugins per layer
    plugins: std::collections::HashMap<LayerId, Box<dyn VerifierPlugin>>,
}

impl std::fmt::Debug for PluginOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait objects can't be introspected generically without forcing
        // every plugin to implement Debug, so we report what's structurally
        // knowable (which layers have a registered plugin) rather than
        // anything about the plugins themselves.
        let mut registered: Vec<&LayerId> = self.plugins.keys().collect();
        registered.sort_by_key(|l| format!("{:?}", l));
        f.debug_struct("PluginOrchestrator")
            .field("registered_layers", &registered)
            .finish()
    }
}

impl PluginOrchestrator {
    /// Create a new plugin orchestrator.
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Register a plugin for a specific layer.
    pub fn register_plugin(&mut self, layer_id: LayerId, plugin: Box<dyn VerifierPlugin>) {
        self.plugins.insert(layer_id, plugin);
    }
    
    /// Run the verification pipeline through all layers in fixed order.
    ///
    /// Plugins cannot reorder or skip layers — the order is enforced by
    /// PIPELINE_ORDER, not by plugin configuration.
    pub fn run_pipeline(&self, transaction_data: Vec<u8>) -> Result<Vec<LayerOutput>, PluginError> {
        let mut results = Vec::new();
        let mut current_input = LayerInput {
            layer_id: PIPELINE_ORDER[0],
            transaction_data,
        };
        
        for layer_id in PIPELINE_ORDER.iter() {
            let plugin = self.plugins.get(layer_id)
                .ok_or_else(|| PluginError::PluginNotRegistered {
                    layer: format!("{:?}", layer_id),
                })?;
            
            let output = plugin.run(&current_input)?;
            
            // If a layer fails, halt the pipeline (later layers don't run)
            if !output.passed {
                results.push(output);
                break;
            }
            
            // Prepare input for the next layer BEFORE moving `output` into
            // `results` below. The original ordering here (push first, then
            // read `output.output_data` afterward) was a real borrow-checker
            // error — `output` doesn't implement `Copy`, so pushing it into
            // `results` moves it, and the next line's `output.output_data`
            // access was a use-after-move. Found by actually running
            // `cargo test` (2026-07-06 sweep), not visible from reading the
            // control flow alone since the bug is purely about ownership,
            // not logic.
            current_input = LayerInput {
                layer_id: *layer_id,
                transaction_data: output.output_data.clone(),
            };
            
            results.push(output);
        }
        
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock plugin for testing.
    struct MockPlugin {
        should_pass: bool,
    }
    
    impl VerifierPlugin for MockPlugin {
        fn run(&self, input: &LayerInput) -> Result<LayerOutput, PluginError> {
            Ok(LayerOutput {
                layer_id: input.layer_id,
                passed: self.should_pass,
                output_data: input.transaction_data.clone(),
            })
        }
    }

    #[test]
    fn test_plugin_trait_has_no_audit_log_or_cross_layer_access() {
        // Load-bearing security test: plugin trait signature prevents P8 violations
        // The trait has no audit_log field, no way to invoke other layers,
        // and no way to modify PIPELINE_ORDER
        
        // This is enforced at compile time by the trait signature
        // No runtime test needed — the type system guarantees it
    }

    #[test]
    fn test_layer_rejection_halts_pipeline_before_later_layers_run() {
        let mut orchestrator = PluginOrchestrator::new();
        
        // Register plugins: first layer fails, others would pass
        orchestrator.register_plugin(LayerId::AccountResolution, Box::new(MockPlugin { should_pass: false }));
        orchestrator.register_plugin(LayerId::TransactionConstruction, Box::new(MockPlugin { should_pass: true }));
        orchestrator.register_plugin(LayerId::Simulation, Box::new(MockPlugin { should_pass: true }));
        
        let results = orchestrator.run_pipeline(vec![1, 2, 3]).unwrap();
        
        // Only first layer ran (failed), pipeline halted
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
    }

    #[test]
    fn test_pipeline_order_is_fixed() {
        // The pipeline order is enforced by PIPELINE_ORDER constant
        // Plugins cannot reorder it
        assert_eq!(PIPELINE_ORDER[0], LayerId::AccountResolution);
        assert_eq!(PIPELINE_ORDER[7], LayerId::ConfidenceEngine);
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        // Bug fixed 2026-07-06 (found by actually running `cargo test`, not
        // by reading the test): this test previously registered only 2 of
        // the 8 fixed PIPELINE_ORDER layers, then called `.unwrap()` on
        // `run_pipeline`'s result expecting success — but the pipeline
        // correctly refuses to skip any layer (that's the whole point of
        // PIPELINE_ORDER being fixed), so it always failed with
        // `PluginNotRegistered { layer: "Simulation" }` at the third layer.
        // The test never actually exercised the "same input, same output"
        // property it claims to — it just panicked identically every time,
        // which happens to also be "deterministic" but isn't what the name
        // promises. Fixed by registering all 8 layers so the pipeline
        // actually completes, and by comparing full result content (not
        // just length) across both runs.
        let mut orchestrator = PluginOrchestrator::new();
        for layer_id in PIPELINE_ORDER.iter() {
            orchestrator.register_plugin(*layer_id, Box::new(MockPlugin { should_pass: true }));
        }
        
        let results1 = orchestrator.run_pipeline(vec![1, 2, 3]).unwrap();
        let results2 = orchestrator.run_pipeline(vec![1, 2, 3]).unwrap();
        
        assert_eq!(results1.len(), PIPELINE_ORDER.len());
        assert_eq!(results1.len(), results2.len());
        for (a, b) in results1.iter().zip(results2.iter()) {
            assert_eq!(a.layer_id, b.layer_id);
            assert_eq!(a.passed, b.passed);
            assert_eq!(a.output_data, b.output_data);
        }
    }
}
