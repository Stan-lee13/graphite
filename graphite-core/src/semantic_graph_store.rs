//! Semantic Graph Storage — ARCHITECTURE.md 3.4
//!
//! Append-only storage for Behavior records, ensuring that verification history
//! is never mutated (Constitution P4). Trust tier computation is performed from
//! evidence, never asserted (Constitution P7/P11).
//!
//! Also implements quarantine (ARCHITECTURE.md 3.8, Self-Healing Semantic
//! Graph): anomaly detection decides WHETHER a record looks
//! anomalous; this module owns the durable, append-only consequence of that
//! decision — `quarantine()` appends a new record with `quarantined: true`
//! and a forced `TrustTier::Unknown`, never mutating the pre-quarantine
//! history (P4) and never letting a caller assign a trust tier directly (P7)
//! even in the quarantine path.
//! for the full detect → quarantine → tier-reflects-it flow.
//!
//! This reference implementation demonstrates the append-only storage SHAPE and
//! the trust tier computation logic. The actual storage backend is a design
//! decision for Phase 1+.

use crate::simulation_integrity::{ComputeBaseline, ComputeUsage};
use std::collections::HashMap;
use thiserror::Error;

// Reuse the canonical `TrustTier` from `confidence_engine` rather than
// redefining an identical, differently-typed enum here. Found during the
// 2026-07-06 production-readiness sweep: this module previously declared
// its own `TrustTier` with identical variants to `confidence_engine::TrustTier`
// — two distinct types with the same name and shape is exactly the kind of
// thing that silently breaks a `use graphite_core::*` import somewhere
// downstream (whichever one the glob resolves to "wins," and the other
// becomes a confusing type-mismatch error at the call site). There is
// exactly one Trust Tier concept in ARCHITECTURE.md (3.5) — it should be
// exactly one Rust type.
pub use crate::confidence_engine::TrustTier;

/// Error cases for Semantic Graph operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SemanticGraphError {
    #[error("behavior record not found for program {program_id}")]
    NotFound { program_id: String },
    #[error("attempted to mutate append-only record")]
    MutationAttempted,
    #[error("invalid behavior record: {reason}")]
    InvalidRecord { reason: String },
}

/// Behavior record for a protocol or program.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Behavior {
    /// Program ID
    pub program_id: String,
    /// Version label
    pub version: String,
    /// Expected state changes
    pub expected_state_changes: Vec<String>,
    /// Allowed CPI targets
    pub allowed_cpis: Vec<String>,
    /// Current trust tier (computed, not asserted — see `append` and
    /// `quarantine`, both of which recompute this field internally rather
    /// than trusting whatever the caller set on the input struct)
    pub trust_tier: TrustTier,
    /// Evidence contributing to trust tier
    pub evidence: BehaviorEvidence,
    /// Whether this record has been quarantined by Self-Healing
    /// (ARCHITECTURE.md 3.8). Quarantine is applied via `quarantine()`,
    /// never by constructing a `Behavior` with this set directly and
    /// calling `append` — `append` always resets this to `false`.
    pub quarantined: bool,
    /// Human-readable reason for quarantine, set only when `quarantined`
    /// is true.
    pub quarantine_reason: Option<String>,
}

/// Evidence contributing to trust tier computation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct BehaviorEvidence {
    /// Whether manifest is signed
    pub has_signed_manifest: bool,
    /// Number of independent community verifications
    pub community_verified_count: u32,
    /// Number of battle-tested transactions
    pub battle_tested_tx_count: u64,
    /// Simulation match count
    pub simulation_match_count: u64,
}

/// Thresholds for trust tier promotion.
pub mod thresholds {
    /// Minimum simulation matches for SimulationValidated tier
    pub const SIMULATION_MATCH: u64 = 3;
    /// Minimum community verifications for CommunityVerified tier
    pub const COMMUNITY_VERIFIED: u32 = 2;
    /// Minimum battle-tested transactions for BattleTested tier
    pub const BATTLE_TESTED_TX: u64 = 1000;
}

/// Compute trust tier from evidence (Constitution P7: computed, never asserted).
///
/// This is a pure, deterministic function (Constitution P2). The same evidence
/// always produces the same trust tier.
pub fn compute_trust_tier(evidence: &BehaviorEvidence) -> TrustTier {
    // Tier 5: Battle-tested (requires volume AND independent credibility)
    if evidence.battle_tested_tx_count >= thresholds::BATTLE_TESTED_TX
        && (evidence.has_signed_manifest
            || evidence.community_verified_count >= thresholds::COMMUNITY_VERIFIED)
    {
        return TrustTier::BattleTested;
    }

    // Tier 4: Community-verified
    if evidence.community_verified_count >= thresholds::COMMUNITY_VERIFIED {
        return TrustTier::CommunityVerified;
    }

    // Tier 3: Simulation-validated
    if evidence.simulation_match_count >= thresholds::SIMULATION_MATCH {
        return TrustTier::SimulationValidated;
    }

    // Tier 2: Official manifest
    if evidence.has_signed_manifest {
        return TrustTier::OfficialManifest;
    }

    // Tier 0: Unknown — no evidence at all (P7: trust must be earned)
    if evidence.battle_tested_tx_count == 0
        && evidence.community_verified_count == 0
        && evidence.simulation_match_count == 0
        && !evidence.has_signed_manifest
    {
        return TrustTier::Unknown;
    }

    // Tier 1: Heuristic-inferred (some signal present but insufficient for higher tiers)
    TrustTier::HeuristicInferred
}

/// Semantic Graph store — append-only Behavior history PLUS the trusted
/// per-program simulation baselines (Constitution security fix: baselines
/// are earned/accumulated here, never accepted from a request body).
///
/// The whole store is serializable so it can be snapshotted to disk
/// (durability) and reloaded on startup.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SemanticGraphStore {
    behaviors: Vec<Behavior>,
    /// Trusted simulation baselines keyed by program ID. Updated ONLY via
    /// `record_simulation` (RPC-verified usage) or `seed_simulation_baseline`
    /// (operator API). Raw request bodies can never write here.
    #[serde(default)]
    baselines: HashMap<String, ComputeBaseline>,
}

impl SemanticGraphStore {
    /// Create a new Semantic Graph store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new Behavior record (append-only, Constitution P4).
    ///
    /// A normal `append` is always a non-quarantined record — this method
    /// unconditionally resets `quarantined` to `false` and clears
    /// `quarantine_reason`, even if the caller constructed a `Behavior` with
    /// those fields already set. Quarantine is a distinct, deliberate action
    /// (`quarantine()`), never a side effect of an ordinary append.
    pub fn append(&mut self, behavior: Behavior) -> Result<(), SemanticGraphError> {
        // Validate record
        if behavior.program_id.is_empty() {
            return Err(SemanticGraphError::InvalidRecord {
                reason: "program_id cannot be empty".to_string(),
            });
        }

        // Compute trust tier from evidence (Constitution P7) — never trust
        // whatever the caller put in `behavior.trust_tier`.
        let trust_tier = compute_trust_tier(&behavior.evidence);

        let mut behavior = behavior;
        behavior.trust_tier = trust_tier;
        behavior.quarantined = false;
        behavior.quarantine_reason = None;

        // Append (never mutate existing)
        self.behaviors.push(behavior);
        Ok(())
    }

    /// Quarantine the latest record for `program_id` (ARCHITECTURE.md 3.8,
    /// Self-Healing Semantic Graph).
    ///
    /// This is itself an APPEND, not a mutation (Constitution P4): it clones
    /// the latest record, marks the clone quarantined with a forced
    /// `TrustTier::Unknown` (Constitution P7 — quarantine status is an input
    /// to trust tier computation, never a direct assignment bypassing it),
    /// and pushes the clone as a new entry. The original pre-quarantine
    /// record remains in history, queryable via `get_all_versions`, and
    /// still reports whatever tier its evidence legitimately earned at the
    /// time — quarantine does not rewrite the past, it adds a new fact.
    ///
    /// Returns `SemanticGraphError::NotFound` if no record exists yet for
    /// `program_id` — there is nothing to quarantine.
    pub fn quarantine(
        &mut self,
        program_id: &str,
        reason: String,
    ) -> Result<(), SemanticGraphError> {
        let latest = self
            .get(program_id)
            .ok_or_else(|| SemanticGraphError::NotFound {
                program_id: program_id.to_string(),
            })?
            .clone();

        let quarantined_record = Behavior {
            trust_tier: TrustTier::Unknown,
            quarantined: true,
            quarantine_reason: Some(reason),
            ..latest
        };

        self.behaviors.push(quarantined_record);
        Ok(())
    }

    /// Read-only view of the full append-only behavior history (all programs,
    /// all versions). Used by observability/dashboard reads — never mutated.
    pub fn behaviors(&self) -> &[Behavior] {
        &self.behaviors
    }

    /// Read-only view of the trusted simulation baselines. Used by
    /// observability/dashboard reads — never mutated.
    pub fn baselines(&self) -> &HashMap<String, ComputeBaseline> {
        &self.baselines
    }

    /// Get Behavior record for a program ID (latest version — reflects
    /// quarantine if `quarantine()` was ever called for this program, since
    /// quarantine appends a new, newer record).
    pub fn get(&self, program_id: &str) -> Option<&Behavior> {
        self.behaviors
            .iter()
            .rev()
            .find(|b| b.program_id == program_id)
    }

    /// Get all Behavior records for a program ID (all versions, append-only
    /// history — includes pre-quarantine records with their original,
    /// legitimately-earned trust tier, per Constitution P4).
    pub fn get_all_versions(&self, program_id: &str) -> Vec<&Behavior> {
        self.behaviors
            .iter()
            .filter(|b| b.program_id == program_id)
            .collect()
    }

    /// Get the trusted simulation baseline for a program, if one exists.
    pub fn get_simulation_baseline(&self, program_id: &str) -> Option<&ComputeBaseline> {
        self.baselines.get(program_id)
    }

    /// Record observed simulation usage for a program (Welford update).
    ///
    /// SECURITY: this is the ONLY trusted write path for baselines. Call it
    /// with RPC-verified usage (simulateTransaction results), never with
    /// raw request-body values — otherwise an attacker who controls the
    /// request could normalize their own divergence.
    ///
    /// Returns the updated baseline.
    pub fn record_simulation(&mut self, program_id: &str, usage: &ComputeUsage) -> ComputeBaseline {
        let entry = self.baselines.entry(program_id.to_string()).or_default();
        crate::simulation_integrity::update_baseline(
            entry,
            usage.compute_units,
            usage.account_writes,
            usage.cpi_hops,
        );
        entry.clone()
    }

    /// Trusted operator API: seed or override a program's simulation
    /// baseline (e.g. restoring a previous deployment's export). Not exposed
    /// over the wire — server operators call this at startup.
    ///
    /// SECURITY: the baseline is VALIDATED before storage. A NaN/Infinity or
    /// negative baseline would otherwise make every subsequent integrity check
    /// for that program fail-closed (or, worse, silently skew every z-score)
    /// with no recovery short of reseeding — a single corrupt seed becomes a
    /// permanent DoS. An empty program ID is rejected for the same reason
    /// `append` rejects one: it is a malformed key that can never correspond
    /// to a real on-chain program, and accepting it would plant a poison
    /// entry that survives snapshot restore. Returns an error instead of
    /// storing poison.
    pub fn seed_simulation_baseline(
        &mut self,
        program_id: &str,
        baseline: ComputeBaseline,
    ) -> Result<(), SemanticGraphError> {
        // GAP-2026-08-06-9: whitespace-only is the same poison-key class as
        // empty (`"   ".is_empty()` is false, so a bare is_empty() check lets
        // a whitespace key through that can never match a real base58 program
        // ID and survives snapshot restore). Reject after trimming.
        if program_id.trim().is_empty() {
            return Err(SemanticGraphError::InvalidRecord {
                reason: "program_id cannot be empty or whitespace-only".to_string(),
            });
        }
        validate_baseline(&baseline)?;
        self.baselines.insert(program_id.to_string(), baseline);
        Ok(())
    }

    /// Serialize the store to JSON (durability snapshot).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a store snapshot. On failure, callers should start fresh
    /// (fail-closed: a corrupt snapshot must not silently lose data, but a
    /// fresh store is still safe — tiers and baselines are re-earned).
    ///
    /// Defensively DROPS any baseline that fails validation (e.g. a poisoned
    /// snapshot written by an older, pre-validation build). An invalid
    /// baseline must never reach the integrity layer.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut store: SemanticGraphStore = serde_json::from_str(json)?;
        store.baselines.retain(|_, b| validate_baseline(b).is_ok());
        Ok(store)
    }
}

/// Validate a simulation baseline before it enters the trusted accumulator.
/// Usage counts are non-negative integers, so means and standard deviations
/// must be finite and non-negative. Rejects NaN/Infinity/negative values.
pub fn validate_baseline(baseline: &ComputeBaseline) -> Result<(), SemanticGraphError> {
    let fields = [
        ("mean_compute_units", baseline.mean_compute_units),
        ("std_compute_units", baseline.std_compute_units),
        ("mean_account_writes", baseline.mean_account_writes),
        ("std_account_writes", baseline.std_account_writes),
        ("mean_cpi_hops", baseline.mean_cpi_hops),
        ("std_cpi_hops", baseline.std_cpi_hops),
    ];
    for (name, value) in fields {
        if !value.is_finite() {
            return Err(SemanticGraphError::InvalidRecord {
                reason: format!("baseline field {} must be finite (got {})", name, value),
            });
        }
        if value < 0.0 {
            return Err(SemanticGraphError::InvalidRecord {
                reason: format!(
                    "baseline field {} must be non-negative (got {})",
                    name, value
                ),
            });
        }
    }
    // A fully-degenerate COMPUTE baseline (zero mean AND zero variance) is
    // meaningless: every integrity check against it would fail-closed,
    // permanently blocking the program until an operator reseeds (the same
    // permanent-DoS class as NaN poisoning). Reject it at the seed/restore
    // boundary instead of letting the state exist. Note this ONLY applies to
    // the compute pair — a writes/hops pair of 0/0 means "signal never
    // observed" and is legitimate.
    if baseline.std_compute_units == 0.0 && baseline.mean_compute_units == 0.0 {
        return Err(SemanticGraphError::InvalidRecord {
            reason: "compute baseline is degenerate (zero mean and zero variance)".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_rejects_nan_and_negative_baselines() {
        let mut store = SemanticGraphStore::new();

        // NaN mean — would permanently fail-closed every check.
        let nan = ComputeBaseline {
            mean_compute_units: f64::NAN,
            ..Default::default()
        };
        assert!(store.seed_simulation_baseline("p1", nan).is_err());
        assert!(
            store.get_simulation_baseline("p1").is_none(),
            "poison must not be stored"
        );

        // Negative mean — would skew every z-score.
        let negative = ComputeBaseline {
            mean_compute_units: -100.0,
            std_compute_units: 10.0,
            sample_count: 50,
            ..Default::default()
        };
        assert!(store.seed_simulation_baseline("p2", negative).is_err());
        assert!(store.get_simulation_baseline("p2").is_none());

        // Infinity std.
        let inf = ComputeBaseline {
            mean_compute_units: 100.0,
            std_compute_units: f64::INFINITY,
            sample_count: 50,
            ..Default::default()
        };
        assert!(store.seed_simulation_baseline("p3", inf).is_err());
        assert!(store.get_simulation_baseline("p3").is_none());

        // A valid baseline is stored.
        let valid = ComputeBaseline {
            mean_compute_units: 100.0,
            std_compute_units: 10.0,
            sample_count: 50,
            ..Default::default()
        };
        assert!(store.seed_simulation_baseline("p4", valid).is_ok());
        assert!(store.get_simulation_baseline("p4").is_some());

        // Degenerate (zero mean AND zero variance) compute baseline — would
        // permanently fail-closed every check; rejected at the seed boundary.
        let degenerate = ComputeBaseline {
            mean_compute_units: 0.0,
            std_compute_units: 0.0,
            sample_count: 100,
            ..Default::default()
        };
        assert!(store.seed_simulation_baseline("p5", degenerate).is_err());
        assert!(store.get_simulation_baseline("p5").is_none());

        // Zero-variance with a NONZERO mean (all identical samples) is valid
        // and must still be accepted — the integrity layer handles it.
        let zero_var = ComputeBaseline {
            mean_compute_units: 1000.0,
            std_compute_units: 0.0,
            sample_count: 100,
            ..Default::default()
        };
        assert!(store.seed_simulation_baseline("p6", zero_var).is_ok());
        assert!(store.get_simulation_baseline("p6").is_some());
    }

    #[test]
    fn test_seed_rejects_empty_program_id() {
        let mut store = SemanticGraphStore::new();
        let valid = ComputeBaseline {
            mean_compute_units: 100.0,
            std_compute_units: 10.0,
            sample_count: 50,
            ..Default::default()
        };
        let result = store.seed_simulation_baseline("", valid);
        assert!(
            result.is_err(),
            "empty program_id must be rejected (rule 10)"
        );
        assert!(
            store.get_simulation_baseline("").is_none(),
            "empty program_id baseline must not be stored"
        );
    }

    /// GAP-2026-08-06-9: whitespace-only program_id must be rejected too —
    /// it is the same poison-key class as empty (`"   ".is_empty()` is false,
    /// so a bare is_empty() check silently plants a whitespace key that can
    /// never match a real base58 program ID and survives snapshot restore).
    #[test]
    fn test_seed_rejects_whitespace_only_program_id() {
        let mut store = SemanticGraphStore::new();
        let valid = ComputeBaseline {
            mean_compute_units: 100.0,
            std_compute_units: 10.0,
            sample_count: 50,
            ..Default::default()
        };
        for bad in [" ", "   ", "\t", "\n"] {
            let result = store.seed_simulation_baseline(bad, valid.clone());
            assert!(
                result.is_err(),
                "whitespace-only program_id {:?} must be rejected (GAP-9)",
                bad
            );
            assert!(
                store.get_simulation_baseline(bad).is_none(),
                "whitespace-only program_id {:?} baseline must not be stored",
                bad
            );
        }
    }

    #[test]
    fn test_from_json_drops_poisoned_baselines() {
        let mut store = SemanticGraphStore::new();
        let good = ComputeBaseline {
            mean_compute_units: 100.0,
            std_compute_units: 10.0,
            sample_count: 50,
            ..Default::default()
        };
        store.seed_simulation_baseline("good", good).unwrap();

        let json = store.to_json().unwrap();
        // Simulate a poisoned snapshot: inject a NEGATIVE mean (the one
        // non-finite poison that is actually representable in JSON) via raw
        // string surgery. NaN/Infinity cannot be written by serde_json, so a
        // snapshot carrying them would fail to parse entirely (callers start
        // fresh — already fail-closed).
        let poisoned = json.replacen("\"good\"", "\"bad\"", 1);
        let poisoned = poisoned.replace(
            "\"mean_compute_units\":100.0",
            "\"mean_compute_units\":-100.0",
        );
        let restored = SemanticGraphStore::from_json(&poisoned).unwrap();
        assert!(
            restored.get_simulation_baseline("bad").is_none(),
            "poisoned baseline must be dropped on restore"
        );
    }

    #[test]
    fn test_append_only_enforcement() {
        let mut store = SemanticGraphStore::new();

        let behavior1 = Behavior {
            program_id: "test_program".to_string(),
            version: "1.0".to_string(),
            expected_state_changes: vec!["transfer".to_string()],
            allowed_cpis: vec![],
            trust_tier: TrustTier::Unknown,
            evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 0,
                battle_tested_tx_count: 0,
                simulation_match_count: 0,
            },
            quarantined: false,
            quarantine_reason: None,
        };

        store.append(behavior1).unwrap();

        // Cannot mutate existing record - only append new versions
        assert_eq!(store.behaviors.len(), 1);
    }

    #[test]
    fn test_trust_tier_computed_from_evidence() {
        let evidence = BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 0,
            battle_tested_tx_count: 0,
            simulation_match_count: 0,
        };

        let tier = compute_trust_tier(&evidence);
        assert_eq!(tier, TrustTier::OfficialManifest);
    }

    #[test]
    fn test_battle_tested_requires_independent_credibility() {
        // Volume alone cannot reach Tier 5 (Constitution P7/P11)
        let evidence = BehaviorEvidence {
            has_signed_manifest: false,
            community_verified_count: 0,
            battle_tested_tx_count: 1500, // High volume
            simulation_match_count: 10,
        };

        let tier = compute_trust_tier(&evidence);
        assert_ne!(tier, TrustTier::BattleTested);
    }

    #[test]
    fn test_deterministic_same_evidence_same_tier() {
        let evidence = BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 2,
            battle_tested_tx_count: 100,
            simulation_match_count: 5,
        };

        let tier1 = compute_trust_tier(&evidence);
        let tier2 = compute_trust_tier(&evidence);

        assert_eq!(tier1, tier2);
    }

    #[test]
    fn test_get_returns_latest_version() {
        let mut store = SemanticGraphStore::new();

        store
            .append(Behavior {
                program_id: "test".to_string(),
                version: "1.0".to_string(),
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                trust_tier: TrustTier::Unknown,
                evidence: BehaviorEvidence {
                    has_signed_manifest: true,
                    community_verified_count: 0,
                    battle_tested_tx_count: 0,
                    simulation_match_count: 0,
                },
                quarantined: false,
                quarantine_reason: None,
            })
            .unwrap();

        store
            .append(Behavior {
                program_id: "test".to_string(),
                version: "2.0".to_string(),
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                trust_tier: TrustTier::Unknown,
                evidence: BehaviorEvidence {
                    has_signed_manifest: true,
                    community_verified_count: 2,
                    battle_tested_tx_count: 0,
                    simulation_match_count: 0,
                },
                quarantined: false,
                quarantine_reason: None,
            })
            .unwrap();

        let latest = store.get("test").unwrap();
        assert_eq!(latest.version, "2.0");
    }

    fn sample_behavior(program_id: &str, version: &str, evidence: BehaviorEvidence) -> Behavior {
        Behavior {
            program_id: program_id.to_string(),
            version: version.to_string(),
            expected_state_changes: vec!["swap".to_string()],
            allowed_cpis: vec![],
            trust_tier: TrustTier::Unknown, // ignored by append/quarantine — always recomputed
            evidence,
            quarantined: false,
            quarantine_reason: None,
        }
    }

    /// Restored 2026-07-06 (production-readiness sweep): quarantine was
    /// dropped from this module during the Cargo-crate restructuring, which
    /// anomaly detection → quarantine → trust-tier flow
    /// module's own doc comment describes. This test is the basic contract:
    /// quarantine forces Unknown regardless of how strong the evidence was.
    #[test]
    fn test_quarantine_forces_unknown_tier_regardless_of_evidence() {
        let mut store = SemanticGraphStore::new();
        let strong_evidence = BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 5000,
            simulation_match_count: 50,
        };
        store
            .append(sample_behavior(
                "battle-tested-program",
                "1.0",
                strong_evidence,
            ))
            .unwrap();

        // Before quarantine: legitimately BattleTested.
        assert_eq!(
            store.get("battle-tested-program").unwrap().trust_tier,
            TrustTier::BattleTested
        );

        store
            .quarantine(
                "battle-tested-program",
                "anomalous compute units, z=225.0".to_string(),
            )
            .unwrap();

        let quarantined = store.get("battle-tested-program").unwrap();
        assert!(quarantined.quarantined);
        assert_eq!(quarantined.trust_tier, TrustTier::Unknown);
        assert_eq!(
            quarantined.quarantine_reason.as_deref(),
            Some("anomalous compute units, z=225.0")
        );
    }

    /// Quarantine is an append, not a mutation (Constitution P4): the
    /// pre-quarantine record must remain queryable via `get_all_versions`
    /// and must still report its ORIGINAL, legitimately-earned tier — the
    /// past doesn't get rewritten just because a later version was flagged.
    #[test]
    fn test_quarantine_preserves_pre_quarantine_history() {
        let mut store = SemanticGraphStore::new();
        let strong_evidence = BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 5000,
            simulation_match_count: 50,
        };
        store
            .append(sample_behavior("historic-program", "1.0", strong_evidence))
            .unwrap();
        store
            .quarantine("historic-program", "test reason".to_string())
            .unwrap();

        let versions = store.get_all_versions("historic-program");
        assert_eq!(versions.len(), 2, "quarantine must APPEND, never replace");

        let pre_quarantine = versions[0];
        assert!(!pre_quarantine.quarantined);
        assert_eq!(pre_quarantine.trust_tier, TrustTier::BattleTested);

        let post_quarantine = versions[1];
        assert!(post_quarantine.quarantined);
        assert_eq!(post_quarantine.trust_tier, TrustTier::Unknown);
    }

    /// Quarantining a program with no existing record is an error, not a
    /// silent no-op or an implicitly-created record — there's nothing to
    /// quarantine, and pretending otherwise would hide a caller bug.
    #[test]
    fn test_quarantine_nonexistent_program_returns_not_found() {
        let mut store = SemanticGraphStore::new();
        let result = store.quarantine("never-seen-program", "irrelevant".to_string());
        assert!(matches!(result, Err(SemanticGraphError::NotFound { .. })));
    }

    /// A fresh `append` after a quarantine must NOT inherit the quarantine —
    /// quarantine is a deliberate action, not sticky state that leaks into
    /// unrelated future appends for the same program (e.g. a legitimate
    /// protocol upgrade after an incident is resolved).
    #[test]
    fn test_append_after_quarantine_is_not_quarantined_by_default() {
        let mut store = SemanticGraphStore::new();
        let evidence = BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 0,
            battle_tested_tx_count: 0,
            simulation_match_count: 0,
        };
        store
            .append(sample_behavior(
                "recovering-program",
                "1.0",
                evidence.clone(),
            ))
            .unwrap();
        store
            .quarantine("recovering-program", "incident".to_string())
            .unwrap();
        store
            .append(sample_behavior("recovering-program", "2.0", evidence))
            .unwrap();

        let latest = store.get("recovering-program").unwrap();
        assert!(!latest.quarantined);
        assert_eq!(latest.version, "2.0");
    }
}
