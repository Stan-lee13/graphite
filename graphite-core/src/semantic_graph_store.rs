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
//! even in the quarantine path. See `SemanticGraphStore::quarantine` for the
//! full detect → quarantine → tier-reflects-it flow.
//!
//! This reference implementation demonstrates the append-only storage SHAPE and
//! the trust tier computation logic. The actual storage backend is a design
//! decision for Phase 1+.

use crate::simulation_integrity::{ComputeBaseline, ComputeUsage};
use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

/// How many distinct simulation identities one accumulator remembers
/// (Round 19, F-19-03).
///
/// Round 17 made the same bytes one observation by remembering the last
/// `ROBUST_WINDOW` (256) observation keys, and a key that had fallen out of
/// that window counted again: the reviewer's reproduction took one program's
/// `sample_count` from 257 to 258 with bytes it had already counted. The
/// memory is now exact for the life of the accumulator. It is bounded, and at
/// the bound the accumulator stops LEARNING rather than FORGETTING: an
/// identity it cannot remember is not counted, and is kept in the shadow
/// accumulator instead, where `/health` reports it and an operator can adopt
/// it (`promote_shadow_baseline`, which starts a new accumulator with its own
/// memory). Under-counting is the safe direction; counting an identity twice
/// is the claim this constant exists to keep true.
///
/// 16,384 identities is 128 KiB of fingerprints per program. Every consumer of
/// `sample_count` saturates long before it — the `SimulationMatch` signal at
/// 3, the integrity check's `MIN_SAMPLES` at 10, the robust window at 256.
pub const OBSERVATION_MEMORY: usize = 16_384;

/// The identities one accumulator has counted, as 64-bit fingerprints.
///
/// A fingerprint is the first eight bytes of a domain-separated SHA-256 of
/// the observation key. Two different identities sharing one is the only way
/// the memory can be wrong, and the error is in the safe direction: the
/// second is taken for one already counted and is not counted. At the bound
/// the chance of any collision is below 2^-37.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservationMemory {
    #[serde(with = "fingerprint_codec")]
    fingerprints: BTreeSet<u64>,
}

impl ObservationMemory {
    fn fingerprint(key: &str) -> u64 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"graphite/observation-fingerprint/v1\0");
        h.update(key.as_bytes());
        let d = h.finalize();
        u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    }

    /// Whether this identity has already been counted.
    pub fn contains(&self, key: &str) -> bool {
        self.fingerprints.contains(&Self::fingerprint(key))
    }

    /// How many identities are remembered.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether nothing is remembered yet.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Whether another identity can be remembered.
    pub fn is_full(&self) -> bool {
        self.fingerprints.len() >= OBSERVATION_MEMORY
    }

    fn remember(&mut self, key: &str) {
        self.fingerprints.insert(Self::fingerprint(key));
    }
}

/// Snapshot encoding for `ObservationMemory`: the fingerprints in ascending
/// order, eight big-endian bytes each, base64. A full memory is ~175 KB of
/// JSON rather than the ~330 KB a number array would take, and it is
/// rewritten with every snapshot.
mod fingerprint_codec {
    use base64::Engine;
    use std::collections::BTreeSet;

    pub fn serialize<S: serde::Serializer>(set: &BTreeSet<u64>, s: S) -> Result<S::Ok, S::Error> {
        let mut raw = Vec::with_capacity(set.len() * 8);
        for f in set {
            raw.extend_from_slice(&f.to_be_bytes());
        }
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(raw))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BTreeSet<u64>, D::Error> {
        use serde::de::Error;
        let text: String = serde::Deserialize::deserialize(d)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(D::Error::custom)?;
        if raw.len() % 8 != 0 {
            return Err(D::Error::custom(format!(
                "observation memory is {} bytes, not a whole number of 8-byte fingerprints",
                raw.len()
            )));
        }
        if raw.len() / 8 > super::OBSERVATION_MEMORY {
            return Err(D::Error::custom(format!(
                "observation memory holds {} fingerprints; the bound is {}",
                raw.len() / 8,
                super::OBSERVATION_MEMORY
            )));
        }
        let (words, rest) = raw.as_chunks::<8>();
        debug_assert!(rest.is_empty(), "length checked above");
        Ok(words.iter().map(|c| u64::from_be_bytes(*c)).collect())
    }
}

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
    /// Round 40: the graph's imported evidence describes another cluster.
    #[error("evidence cluster: {reason}")]
    EvidenceCluster { reason: String },
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
    /// Round 40 (R39-CORE-IDENTITY-7): the registry evidence on this record
    /// is a FIRST manifest's, or one no independent replay has validated
    /// since — its fixtures were recorded under the very manifest they were
    /// replayed against, so they agree with it by construction. The tier is
    /// then capped at `HeuristicInferred` ([`compute_trust_tier_for`]) until
    /// an upgrade passes the P10 gate against fixtures an earlier version
    /// pinned (the registry clears it then), or measured volume reaches the
    /// `BattleTested` threshold. Set only by the registry; every other
    /// append carries it forward from the program's previous record, so an
    /// operator's seed cannot clear it. Absent from records written before
    /// Round 40, and from every record that is not so flagged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub first_manifest_unvalidated: bool,
}

/// Evidence contributing to trust tier computation.
///
/// Unknown fields are refused (Round 29, audit 2026-10-20, F4): a misspelled
/// field in an operator's seed or a snapshot is an error, not silently absent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BehaviorEvidence {
    /// Whether manifest is signed
    pub has_signed_manifest: bool,
    /// Number of independent community verifications
    pub community_verified_count: u32,
    /// Number of battle-tested transactions — OPERATOR-ASSERTED (audit
    /// 2026-10-20, G-2). Nothing in the verification pipeline increments it:
    /// it holds whatever an operator seeded (`GraphiteCore::seed_behavior`,
    /// the `graphite evidence` CLI) or a snapshot restored. It is evidence an
    /// operator vouches for, not volume Graphite has observed, and the
    /// `BattleTested` tier it unlocks is an operator's assertion to the same
    /// degree. Since Round 40 an operator can set it from a measurement
    /// instead of a typed number: `graphite evidence import-census` raises it
    /// to the committed census's successful-transaction count
    /// (`census_import`), still an operator action, recorded on the trail.
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
    /// Minimum battle-tested transactions for BattleTested tier — counted
    /// from operator-asserted evidence (see
    /// `BehaviorEvidence::battle_tested_tx_count`).
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

/// The trust tier of a record (Round 40, R39-CORE-IDENTITY-7): what
/// [`compute_trust_tier`] computes from `evidence`, capped at
/// `HeuristicInferred` while `first_manifest_unvalidated` holds.
///
/// A first manifest's registry evidence — a reviewer's signature, community
/// attestations — vouches for a manifest whose replay proved nothing: there
/// was no earlier behaviour to replay it against, and its own fixtures were
/// recorded under it. Those signals count only as "some signal" until the
/// manifest has been held to fixtures it did not write. The cap is lifted by
/// evidence, never by assertion: an upgrade the P10 gate replayed against an
/// earlier version's fixtures (the registry then records the evidence
/// unflagged), or measured battle-tested volume at the `BattleTested`
/// threshold (a census-backed record), which earns its tier as it always
/// did. Operator-asserted signatures or attestations do not lift it.
pub fn compute_trust_tier_for(
    evidence: &BehaviorEvidence,
    first_manifest_unvalidated: bool,
) -> TrustTier {
    let tier = compute_trust_tier(evidence);
    if first_manifest_unvalidated && evidence.battle_tested_tx_count < thresholds::BATTLE_TESTED_TX
    {
        tier.min(TrustTier::HeuristicInferred)
    } else {
        tier
    }
}

/// Semantic Graph store — append-only Behavior history PLUS the trusted
/// per-program simulation baselines (Constitution security fix: baselines
/// are earned/accumulated here, never accepted from a request body).
///
/// The whole store is serializable so it can be snapshotted to disk
/// (durability) and reloaded on startup. Reading a snapshot goes through
/// [`StoreSnapshot`], which recomputes every record's tier and rebuilds the
/// per-program index (Round 29, audit 2026-10-20, G-4).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(from = "StoreSnapshot")]
pub struct SemanticGraphStore {
    behaviors: Vec<Behavior>,
    /// Position in `behaviors` of each program's LATEST record (Round 29,
    /// audit 2026-10-20). `get` — on the verdict path, once per verification
    /// — scanned the whole unbounded history backwards for every lookup.
    /// Derived from `behaviors`, so never written to a snapshot.
    #[serde(skip)]
    latest: HashMap<String, usize>,
    /// Trusted simulation baselines keyed by program ID. Updated ONLY via
    /// `record_simulation` (RPC-verified usage) or `seed_simulation_baseline`
    /// (operator API). Raw request bodies can never write here.
    #[serde(default)]
    baselines: HashMap<String, ComputeBaseline>,
    /// Round 17 (F-16-02): observations the simulator executed cleanly but
    /// the integrity check FLAGGED against the trusted baseline. They never
    /// influence a verdict. They exist so that a baseline frozen by a few
    /// identical early samples is visible (`/health` lists programs whose
    /// shadow has reached `MIN_SAMPLES`) and recoverable (`promote_shadow`,
    /// an operator action) instead of permanent.
    #[serde(default)]
    shadow_baselines: HashMap<String, ComputeBaseline>,
    /// Round 19 (F-19-03): the identities each trusted baseline has counted,
    /// for the life of that baseline — see `OBSERVATION_MEMORY`.
    #[serde(default)]
    observed: HashMap<String, ObservationMemory>,
    /// The same for each shadow accumulator.
    #[serde(default)]
    shadow_observed: HashMap<String, ObservationMemory>,
    /// Roadmap R-M1: the deployment of each manifested program as Graphite
    /// last saw it (the loader's deploy slot and upgrade authority), so an
    /// upgrade is noticed the first time a transaction reaches the program
    /// after it. Omitted from the snapshot while empty.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    deployments: HashMap<String, ObservedDeployment>,
    /// Round 30 (G-03): trusted baselines per transaction SHAPE — the
    /// primary program, its instruction and the other programs the
    /// transaction invokes at top level (`shape_key`). Written by the same
    /// observations as the program's baseline, and nothing else; what L3
    /// judges by once one has `MIN_SAMPLES`. Never migrated from a
    /// program-level baseline: a shape's evidence is that shape's.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    shape_baselines: HashMap<String, ComputeBaseline>,
    /// Round 30 (G-04): the earliest simulation slot among the observations
    /// each program's current baseline has counted — what the evidence is
    /// bound to, so a deployment newer than it is code the evidence never saw.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    evidence_since_slot: HashMap<String, u64>,
    /// Round 30 (G-04): evidence withdrawn because the code it described was
    /// replaced, kept for audit (`RETIRED_EVIDENCE_KEPT` most recent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_evidence: Vec<RetiredEvidence>,
    /// Round 40 (bootstrap): the genesis hash of the cluster the graph's
    /// imported evidence was measured on (`graphite evidence import-census`:
    /// mainnet-beta). Set by the import, never cleared: a Core that attaches
    /// an RPC must confirm the RPC serves this cluster before it uses the
    /// graph (`GraphiteCore::confirm_evidence_cluster`; the server refuses to
    /// start otherwise). Omitted from the snapshot while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence_genesis: Option<String>,
    /// The baseline schema this store follows. Always written as
    /// `BASELINE_SCHEMA`; a snapshot without it was written before Round 30.
    #[serde(default, serialize_with = "write_baseline_schema")]
    baseline_schema: u32,
}

fn write_baseline_schema<S: serde::Serializer>(_: &u32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u32(BASELINE_SCHEMA)
}

/// The baseline schema written since Round 30: shape baselines exist, and
/// every mature baseline carries its `BaselineAnchor`.
pub const BASELINE_SCHEMA: u32 = 2;

/// How many retired-evidence records a store keeps (Round 30, G-04).
pub const RETIRED_EVIDENCE_KEPT: usize = 1024;

/// Evidence withdrawn from a program because its code changed (Round 30,
/// G-04): what was withdrawn, why, and the deployments either side.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RetiredEvidence {
    pub program_id: String,
    pub reason: String,
    /// The deployment the evidence described, when Graphite had seen it.
    pub previous_deployment: Option<ObservedDeployment>,
    /// The deployment that replaced it.
    pub deployment: ObservedDeployment,
    /// The retired program-level baseline's sample count (0: none).
    pub baseline_samples: u64,
    /// How many shape baselines were retired with it.
    pub shape_baselines: usize,
    /// The Behavior evidence the program carried before the reset.
    pub evidence: Option<BehaviorEvidence>,
}

/// A snapshot of [`SemanticGraphStore`] as written — every persisted field,
/// read before the store is rebuilt from it.
#[derive(serde::Deserialize)]
struct StoreSnapshot {
    behaviors: Vec<Behavior>,
    #[serde(default)]
    baselines: HashMap<String, ComputeBaseline>,
    #[serde(default)]
    shadow_baselines: HashMap<String, ComputeBaseline>,
    #[serde(default)]
    observed: HashMap<String, ObservationMemory>,
    #[serde(default)]
    shadow_observed: HashMap<String, ObservationMemory>,
    #[serde(default)]
    deployments: HashMap<String, ObservedDeployment>,
    #[serde(default)]
    shape_baselines: HashMap<String, ComputeBaseline>,
    #[serde(default)]
    evidence_since_slot: HashMap<String, u64>,
    #[serde(default)]
    retired_evidence: Vec<RetiredEvidence>,
    #[serde(default)]
    evidence_genesis: Option<String>,
    #[serde(default)]
    baseline_schema: u32,
}

impl From<StoreSnapshot> for SemanticGraphStore {
    /// G-4 (Round 29, audit 2026-10-20): a restored record's `trust_tier`
    /// was taken from the snapshot as written, so a tier the evidence does
    /// not support — a hand-edited snapshot, or one written before a
    /// threshold changed — came back into force. P7 says a tier is computed,
    /// never asserted, and a snapshot is a document like any other: every
    /// record's tier is recomputed from its evidence (a quarantined record
    /// stays `Unknown`), and the index is rebuilt.
    fn from(s: StoreSnapshot) -> Self {
        let mut store = SemanticGraphStore {
            behaviors: Vec::with_capacity(s.behaviors.len()),
            latest: HashMap::new(),
            baselines: s.baselines,
            shadow_baselines: s.shadow_baselines,
            observed: s.observed,
            shadow_observed: s.shadow_observed,
            deployments: s.deployments,
            shape_baselines: if s.baseline_schema >= BASELINE_SCHEMA {
                s.shape_baselines
            } else {
                HashMap::new()
            },
            evidence_since_slot: s.evidence_since_slot,
            retired_evidence: s.retired_evidence,
            evidence_genesis: s.evidence_genesis,
            baseline_schema: BASELINE_SCHEMA,
        };
        // Round 30 (G-03): a mature baseline written before anchors existed
        // is anchored where it stands. What it learned before is kept; it
        // can no longer drift past it.
        for b in store
            .baselines
            .values_mut()
            .chain(store.shadow_baselines.values_mut())
            .chain(store.shape_baselines.values_mut())
        {
            if b.anchor.is_none() && b.sample_count >= crate::simulation_integrity::MIN_SAMPLES {
                b.anchor = Some(crate::simulation_integrity::anchor_of(b));
            }
        }
        for mut b in s.behaviors {
            b.trust_tier = if b.quarantined {
                TrustTier::Unknown
            } else {
                compute_trust_tier_for(&b.evidence, b.first_manifest_unvalidated)
            };
            store.push_behavior(b);
        }
        store
    }
}

/// A program's code as Graphite last saw it (roadmap R-M1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservedDeployment {
    /// The slot the loader says the code was last deployed at.
    pub deploy_slot: u64,
    /// Who may replace the code (`None`: no one).
    pub upgrade_authority: Option<String>,
}

/// What a deployment observation says about the previous one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentChange {
    /// The first time Graphite has seen this program's deployment.
    First,
    /// The same code under the same authority.
    Same,
    /// Redeployed, or its upgrade authority changed, since it was last seen.
    Changed { previous: ObservedDeployment },
}

impl SemanticGraphStore {
    /// Create a new Semantic Graph store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new Behavior record (append-only, Constitution P4).
    ///
    /// A caller can never set quarantine state through this method: the fields
    /// are ignored, because quarantine is a distinct, deliberate action
    /// (`quarantine()`), never a side effect of an ordinary append.
    ///
    /// An ACTIVE quarantine is carried forward onto the new record.
    ///
    /// This inverts the behaviour up to 2026-09-05, which cleared quarantine on
    /// any append so that "a legitimate protocol upgrade after an incident is
    /// resolved" would restore the program. The problem is who gets to declare
    /// the incident resolved. `manifest_registry::submit` appends, and a
    /// resubmission at the same trust tier is not a promotion, so it is not
    /// even P10-gated — which made an upgrade a self-service un-quarantine,
    /// available to the very actor whose program was withdrawn from trust, with
    /// no review of whether the new version fixed anything. Nothing verified
    /// that the upgrade addressed the incident; shipping any new version was
    /// enough.
    ///
    /// Recovery is still possible and is still an append — it just has to be
    /// asked for: `lift_quarantine()` is the deliberate counterpart, and it is
    /// an operator action rather than a consequence of publishing.
    pub fn append(&mut self, behavior: Behavior) -> Result<(), SemanticGraphError> {
        self.append_record(behavior, true)
    }

    /// `append`, with the registry's own say over
    /// [`Behavior::first_manifest_unvalidated`] when `carry_unvalidated` is
    /// false (Round 40): every other writer carries the flag forward.
    fn append_record(
        &mut self,
        behavior: Behavior,
        carry_unvalidated: bool,
    ) -> Result<(), SemanticGraphError> {
        // Validate record
        if behavior.program_id.is_empty() {
            return Err(SemanticGraphError::InvalidRecord {
                reason: "program_id cannot be empty".to_string(),
            });
        }

        let active_quarantine = self
            .get(&behavior.program_id)
            .filter(|b| b.quarantined)
            .map(|b| b.quarantine_reason.clone());

        let mut behavior = behavior;
        if carry_unvalidated {
            // Round 40 (R39-CORE-IDENTITY-7): only an independent replay
            // clears it, and only the registry runs one.
            behavior.first_manifest_unvalidated |= self
                .get(&behavior.program_id)
                .is_some_and(|b| b.first_manifest_unvalidated);
        }
        match active_quarantine {
            Some(reason) => {
                // P7: quarantine is an input to tier computation, so a
                // quarantined record's tier is Unknown regardless of evidence.
                behavior.trust_tier = TrustTier::Unknown;
                behavior.quarantined = true;
                behavior.quarantine_reason = reason;
            }
            None => {
                // Compute trust tier from evidence (Constitution P7) — never
                // trust whatever the caller put in `behavior.trust_tier`.
                behavior.trust_tier =
                    compute_trust_tier_for(&behavior.evidence, behavior.first_manifest_unvalidated);
                behavior.quarantined = false;
                behavior.quarantine_reason = None;
            }
        }

        // Append (never mutate existing)
        self.push_behavior(behavior);
        Ok(())
    }

    /// Lift an active quarantine (ARCHITECTURE.md 3.8), the deliberate
    /// counterpart to `quarantine()`.
    ///
    /// Like quarantine, this is an APPEND, not a mutation (P4): the quarantine
    /// record stays in history and this adds a new fact. The restored tier is
    /// RECOMPUTED from the record's evidence (P7) rather than restored from
    /// whatever it was before — trust is re-derived, never handed back.
    ///
    /// Returns `NotFound` when the program has no record, and
    /// `InvalidRecord` when it is not currently quarantined — lifting nothing
    /// would otherwise append a confusing no-op record to an audit trail whose
    /// value is that every entry means something.
    pub fn lift_quarantine(&mut self, program_id: &str) -> Result<(), SemanticGraphError> {
        let latest = self
            .get(program_id)
            .ok_or_else(|| SemanticGraphError::NotFound {
                program_id: program_id.to_string(),
            })?
            .clone();

        if !latest.quarantined {
            return Err(SemanticGraphError::InvalidRecord {
                reason: format!("program {program_id} is not quarantined"),
            });
        }

        self.push_behavior(Behavior {
            trust_tier: compute_trust_tier_for(&latest.evidence, latest.first_manifest_unvalidated),
            quarantined: false,
            quarantine_reason: None,
            ..latest
        });
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
    /// A program with NO prior record can be quarantined: the entry is created
    /// with no evidence and no version.
    ///
    /// This returned `NotFound` until 2026-09-05, on the reasoning that there
    /// was nothing to quarantine. But the operator asking for this is usually
    /// reacting to an advisory about a program the gate has never had traffic
    /// for — most seed protocols have no behaviour record on a fresh instance —
    /// and telling them "unknown program" when they are trying to block it is
    /// the wrong answer to the right question. Pre-emptive blocking is the
    /// normal case, not the exception.
    ///
    /// Only the empty program id is rejected.
    pub fn quarantine(
        &mut self,
        program_id: &str,
        reason: String,
    ) -> Result<(), SemanticGraphError> {
        if program_id.trim().is_empty() {
            return Err(SemanticGraphError::InvalidRecord {
                reason: "program_id cannot be empty".to_string(),
            });
        }

        let base = self.get(program_id).cloned().unwrap_or_else(|| Behavior {
            program_id: program_id.to_string(),
            version: String::new(),
            expected_state_changes: Vec::new(),
            allowed_cpis: Vec::new(),
            trust_tier: TrustTier::Unknown,
            evidence: BehaviorEvidence::default(),
            quarantined: false,
            quarantine_reason: None,
            first_manifest_unvalidated: false,
        });

        let quarantined_record = Behavior {
            trust_tier: TrustTier::Unknown,
            quarantined: true,
            quarantine_reason: Some(reason),
            ..base
        };

        self.push_behavior(quarantined_record);
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

    /// Record a program's current deployment and say how it compares with
    /// the last one seen. The record is replaced on a change, so each upgrade
    /// is reported once.
    pub fn observe_deployment(
        &mut self,
        program_id: &str,
        now: ObservedDeployment,
    ) -> DeploymentChange {
        match self.deployments.insert(program_id.to_string(), now.clone()) {
            None => DeploymentChange::First,
            Some(previous) if previous == now => DeploymentChange::Same,
            Some(previous) => DeploymentChange::Changed { previous },
        }
    }

    /// The deployment last seen for a program.
    pub fn observed_deployment(&self, program_id: &str) -> Option<&ObservedDeployment> {
        self.deployments.get(program_id)
    }

    /// Get Behavior record for a program ID (latest version — reflects
    /// quarantine if `quarantine()` was ever called for this program, since
    /// quarantine appends a new, newer record).
    pub fn get(&self, program_id: &str) -> Option<&Behavior> {
        self.latest
            .get(program_id)
            .and_then(|&i| self.behaviors.get(i))
    }

    /// The one way a record enters the history: appended, and indexed as its
    /// program's latest.
    fn push_behavior(&mut self, behavior: Behavior) {
        self.latest
            .insert(behavior.program_id.clone(), self.behaviors.len());
        self.behaviors.push(behavior);
    }

    /// Append a Behavior whose evidence is the REGISTRY's — a signature and
    /// attestations for one manifest version — keeping the evidence the
    /// registry does not speak to (Round 29, audit 2026-10-20, G-3).
    ///
    /// `manifest_registry::submit` appended a record carrying only what the
    /// submission evidenced, so accepting a manifest reset the program's
    /// operator-seeded `battle_tested_tx_count` and `simulation_match_count`
    /// to zero: a program at `BattleTested` dropped to `OfficialManifest` the
    /// moment its manifest was corrected. Those counts are facts about the
    /// program, not about a manifest version, and carry forward from the
    /// program's latest record. The signature and attestation fields are
    /// facts about the version being accepted and come from `behavior`.
    pub fn append_registry_evidence(
        &mut self,
        behavior: Behavior,
    ) -> Result<(), SemanticGraphError> {
        let mut behavior = behavior;
        if let Some(prev) = self.get(&behavior.program_id) {
            behavior.evidence.battle_tested_tx_count = behavior
                .evidence
                .battle_tested_tx_count
                .max(prev.evidence.battle_tested_tx_count);
            behavior.evidence.simulation_match_count = behavior
                .evidence
                .simulation_match_count
                .max(prev.evidence.simulation_match_count);
        }
        // Round 40 (R39-CORE-IDENTITY-7): the registry says whether its
        // evidence has been validated by an independent replay; nothing is
        // carried forward here.
        self.append_record(behavior, false)
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

    /// Read-only view of the shadow accumulators (Round 17, F-16-02).
    pub fn shadow_baselines(&self) -> &HashMap<String, ComputeBaseline> {
        &self.shadow_baselines
    }

    /// Record a flagged-but-executed observation in the program's shadow
    /// accumulator. Never consulted by any verdict.
    pub fn record_shadow_simulation(
        &mut self,
        program_id: &str,
        usage: &ComputeUsage,
        observation_key: Option<&str>,
    ) -> ComputeBaseline {
        // Same identity rule as the trusted accumulator: one transaction
        // flagged ten times is one refused observation, not a frozen
        // baseline — otherwise a single request could raise the
        // `simulation_baseline_frozen` signal on its own. A full shadow
        // memory drops the observation: the shadow is already past
        // `MIN_SAMPLES` by then, so the signal it exists to raise is raised.
        if let Some(key) = observation_key {
            let memory = self
                .shadow_observed
                .entry(program_id.to_string())
                .or_default();
            if memory.contains(key) || memory.is_full() {
                return self
                    .shadow_baselines
                    .get(program_id)
                    .cloned()
                    .unwrap_or_default();
            }
            memory.remember(key);
        }
        let entry = self
            .shadow_baselines
            .entry(program_id.to_string())
            .or_default();
        crate::simulation_integrity::update_baseline(
            entry,
            usage.compute_units,
            usage.account_writes,
            usage.cpi_hops,
        );
        entry.clone()
    }

    /// How many identities the trusted baseline for `program_id` has counted
    /// and remembers, and whether its memory is full (Round 19).
    pub fn observation_memory(&self, program_id: &str) -> (usize, bool) {
        self.observed
            .get(program_id)
            .map(|m| (m.len(), m.is_full()))
            .unwrap_or((0, false))
    }

    /// Programs whose trusted baseline has refused at least `MIN_SAMPLES`
    /// clean executions: the frozen-baseline signal an operator should see.
    pub fn frozen_baselines(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .shadow_baselines
            .iter()
            .filter(|(_, b)| b.sample_count >= crate::simulation_integrity::MIN_SAMPLES)
            .map(|(p, b)| (p.clone(), b.sample_count))
            .collect();
        out.sort();
        out
    }

    /// Operator action: replace the trusted baseline with the shadow one and
    /// clear the shadow. Refuses when there is no shadow, or the shadow has
    /// fewer than `MIN_SAMPLES` observations (a promotion from a handful of
    /// samples would recreate the freeze it is meant to end).
    pub fn promote_shadow_baseline(
        &mut self,
        program_id: &str,
    ) -> Result<ComputeBaseline, SemanticGraphError> {
        let key = program_id.trim();
        let shadow = self.shadow_baselines.get(key).cloned().ok_or_else(|| {
            SemanticGraphError::InvalidRecord {
                reason: format!("program {key} has no shadow baseline to promote"),
            }
        })?;
        if shadow.sample_count < crate::simulation_integrity::MIN_SAMPLES {
            return Err(SemanticGraphError::InvalidRecord {
                reason: format!(
                    "program {key}: shadow baseline holds {} observation(s); at least {} are needed before it can replace the trusted one",
                    shadow.sample_count,
                    crate::simulation_integrity::MIN_SAMPLES
                ),
            });
        }
        validate_baseline(&shadow)?;
        // Round 30: the operator adopts the shadow's regime, so the anchor is
        // the shadow's as it stands, and the program's shape baselines —
        // learned under the regime being retired — start again (L3 judges by
        // the promoted program baseline meanwhile).
        let mut shadow = shadow;
        shadow.anchor = Some(crate::simulation_integrity::anchor_of(&shadow));
        let prefix = format!("{key}/");
        self.shape_baselines.retain(|k, _| !k.starts_with(&prefix));
        self.baselines.insert(key.to_string(), shadow.clone());
        self.shadow_baselines.remove(key);
        // The adopted accumulator brings the identities it counted; the
        // retired one's memory goes with it. What was counted once in the
        // new baseline is still counted once.
        let memory = self.shadow_observed.remove(key).unwrap_or_default();
        self.observed.insert(key.to_string(), memory);
        Ok(shadow)
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
        self.record_simulation_keyed(program_id, usage, None)
    }

    /// `record_simulation` with the observation's identity
    /// (`tx_artifact::simulation_identity`). An identity this baseline has
    /// already counted is the same simulation seen again: nothing is
    /// recorded, because a call is not an observation (Round 17, F-15-01) —
    /// and that now holds for the life of the baseline, not for its last 256
    /// observations (Round 19, F-19-03).
    ///
    /// When the baseline's memory is full (`OBSERVATION_MEMORY`) a new
    /// identity cannot be remembered, so it is not counted here; it goes to
    /// the shadow accumulator. The trusted baseline stops learning rather
    /// than forgetting what it has counted.
    pub fn record_simulation_keyed(
        &mut self,
        program_id: &str,
        usage: &ComputeUsage,
        observation_key: Option<&str>,
    ) -> ComputeBaseline {
        self.record_observation(program_id, None, usage, observation_key, None)
    }

    /// Record one sound observation (Round 30): into the program's baseline,
    /// into its shape's (`shape_key`) when one is named, and bind the
    /// program's evidence to the earliest simulation `slot` it has counted
    /// (G-04). The identity rule is the program's: an identity the program
    /// has counted is counted nowhere again, and one its full memory cannot
    /// remember goes to the shadow accumulator and to no baseline. A shape
    /// that does not belong to `program_id` is ignored.
    pub fn record_observation(
        &mut self,
        program_id: &str,
        shape: Option<&str>,
        usage: &ComputeUsage,
        observation_key: Option<&str>,
        slot: Option<u64>,
    ) -> ComputeBaseline {
        if let Some(key) = observation_key {
            let memory = self.observed.entry(program_id.to_string()).or_default();
            if memory.contains(key) {
                return self.baselines.get(program_id).cloned().unwrap_or_default();
            }
            if memory.is_full() {
                self.record_shadow_simulation(program_id, usage, Some(key));
                return self.baselines.get(program_id).cloned().unwrap_or_default();
            }
            memory.remember(key);
        }
        let prefix = format!("{program_id}/");
        if let Some(shape) = shape.filter(|s| s.starts_with(&prefix)) {
            let entry = self.shape_baselines.entry(shape.to_string()).or_default();
            crate::simulation_integrity::update_baseline(
                entry,
                usage.compute_units,
                usage.account_writes,
                usage.cpi_hops,
            );
        }
        if let Some(slot) = slot {
            let since = self
                .evidence_since_slot
                .entry(program_id.to_string())
                .or_insert(slot);
            *since = (*since).min(slot);
        }
        let entry = self.baselines.entry(program_id.to_string()).or_default();
        crate::simulation_integrity::update_baseline(
            entry,
            usage.compute_units,
            usage.account_writes,
            usage.cpi_hops,
        );
        entry.clone()
    }

    /// The baseline L3 judges a transaction of `shape` by (Round 30, G-03):
    /// the shape's own once it has `MIN_SAMPLES` observations, else the
    /// program's. The flag says which — `true` for the shape's.
    pub fn baseline_for(
        &self,
        program_id: &str,
        shape: Option<&str>,
    ) -> Option<(&ComputeBaseline, bool)> {
        if let Some(b) = shape.and_then(|s| self.shape_baselines.get(s)) {
            if b.sample_count >= crate::simulation_integrity::MIN_SAMPLES {
                return Some((b, true));
            }
        }
        self.baselines.get(program_id).map(|b| (b, false))
    }

    /// One shape's baseline, mature or not.
    pub fn shape_baseline(&self, shape: &str) -> Option<&ComputeBaseline> {
        self.shape_baselines.get(shape)
    }

    /// Every shape baseline of a program, sorted by key.
    pub fn shape_baselines_of(&self, program_id: &str) -> Vec<(String, ComputeBaseline)> {
        let prefix = format!("{program_id}/");
        let mut out: Vec<(String, ComputeBaseline)> = self
            .shape_baselines
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, b)| (k.clone(), b.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The earliest simulation slot the program's current evidence was
    /// observed at (Round 30, G-04).
    pub fn evidence_since_slot(&self, program_id: &str) -> Option<u64> {
        self.evidence_since_slot.get(program_id).copied()
    }

    /// Bind a program's evidence to `slot`: the earliest slot it describes
    /// (Round 40, bootstrap). Only ever moves the binding EARLIER — an
    /// earlier binding means more deployments count as newer than the
    /// evidence, so the upgrade watch withdraws it in more cases, never
    /// fewer. Used by the census import, whose measurement began at the
    /// census window's oldest slot: with no binding, a first sighting of a
    /// deployment newer than the census would keep the imported volume
    /// ("cannot be dated against this deployment").
    pub fn bind_evidence_to_slot(&mut self, program_id: &str, slot: u64) {
        let since = self
            .evidence_since_slot
            .entry(program_id.to_string())
            .or_insert(slot);
        *since = (*since).min(slot);
    }

    /// Record that the graph holds evidence measured on the cluster whose
    /// genesis hash is `genesis` (Round 40). Set once: evidence of a second
    /// cluster in the same graph is refused, since one Core verifies one
    /// cluster.
    pub fn mark_evidence_genesis(&mut self, genesis: &str) -> Result<(), SemanticGraphError> {
        match &self.evidence_genesis {
            Some(g) if g != genesis => Err(SemanticGraphError::EvidenceCluster {
                reason: format!(
                    "the graph already holds evidence of the cluster whose genesis hash is {g}, not {genesis}"
                ),
            }),
            Some(_) => Ok(()),
            None => {
                self.evidence_genesis = Some(genesis.to_string());
                Ok(())
            }
        }
    }

    /// The genesis hash of the cluster imported evidence describes, if any.
    pub fn evidence_genesis(&self) -> Option<&str> {
        self.evidence_genesis.as_deref()
    }

    /// Evidence retired because a program's code changed, oldest first.
    pub fn retired_evidence(&self) -> &[RetiredEvidence] {
        &self.retired_evidence
    }

    /// Withdraw everything Graphite has learned or been told about a
    /// program's behaviour, because the code it described has been replaced
    /// (Round 30, G-04): its trusted, shadow and shape baselines, the
    /// identities they counted, the slot binding, and the Behavior evidence —
    /// the battle-tested volume and the community attestations were about the
    /// old code. The manifest's own signature is about the manifest and
    /// stays. The Behavior reset is an append (P4) that keeps an active
    /// quarantine; the retired figures are kept in `retired_evidence`.
    ///
    /// The program is back where a program Graphite has never observed
    /// starts: its tier is what its manifest alone earns, its confidence has
    /// no evidence signal, and L3 has no baseline until ten new observations
    /// — refused by every built-in profile until an operator, having
    /// reviewed the new code, seeds its evidence again.
    pub fn retire_program_evidence(
        &mut self,
        program_id: &str,
        reason: String,
        previous_deployment: Option<ObservedDeployment>,
        deployment: ObservedDeployment,
    ) -> RetiredEvidence {
        let baseline_samples = self
            .baselines
            .remove(program_id)
            .map(|b| b.sample_count)
            .unwrap_or(0);
        self.shadow_baselines.remove(program_id);
        self.observed.remove(program_id);
        self.shadow_observed.remove(program_id);
        self.evidence_since_slot.remove(program_id);
        let prefix = format!("{program_id}/");
        let before = self.shape_baselines.len();
        self.shape_baselines.retain(|k, _| !k.starts_with(&prefix));
        let shape_baselines = before - self.shape_baselines.len();
        let evidence = self.get(program_id).map(|b| b.evidence.clone());
        if let Some(latest) = self.get(program_id).cloned() {
            let reset = BehaviorEvidence {
                has_signed_manifest: latest.evidence.has_signed_manifest,
                ..BehaviorEvidence::default()
            };
            if reset != latest.evidence {
                let trust_tier = if latest.quarantined {
                    TrustTier::Unknown
                } else {
                    compute_trust_tier_for(&reset, latest.first_manifest_unvalidated)
                };
                self.push_behavior(Behavior {
                    evidence: reset,
                    trust_tier,
                    ..latest
                });
            }
        }
        let retired = RetiredEvidence {
            program_id: program_id.to_string(),
            reason,
            previous_deployment,
            deployment,
            baseline_samples,
            shape_baselines,
            evidence,
        };
        self.retired_evidence.push(retired.clone());
        let excess = self
            .retired_evidence
            .len()
            .saturating_sub(RETIRED_EVIDENCE_KEPT);
        self.retired_evidence.drain(..excess);
        retired
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
        // Round 30 (G-03): a seeded baseline mature enough to judge is
        // anchored where the operator put it. The program's shape baselines
        // were learned beside the baseline being replaced; they start again.
        let mut baseline = baseline;
        if baseline.anchor.is_none()
            && baseline.sample_count >= crate::simulation_integrity::MIN_SAMPLES
        {
            baseline.anchor = Some(crate::simulation_integrity::anchor_of(&baseline));
        }
        let prefix = format!("{program_id}/");
        self.shape_baselines.retain(|k, _| !k.starts_with(&prefix));
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
    /// Every record's tier is recomputed from its evidence (G-4, see
    /// `StoreSnapshot`). Defensively DROPS any baseline that fails validation
    /// (e.g. a poisoned snapshot written by an older, pre-validation build).
    /// An invalid baseline must never reach the integrity layer.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut store: SemanticGraphStore = serde_json::from_str(json)?;
        store.baselines.retain(|_, b| validate_baseline(b).is_ok());
        store
            .shadow_baselines
            .retain(|_, b| validate_baseline(b).is_ok());
        store
            .shape_baselines
            .retain(|_, b| validate_baseline(b).is_ok());
        Ok(store)
    }
}

/// The key of a transaction's SHAPE (Round 30, G-03): the primary program,
/// the instruction its manifest names, and the set of other programs the
/// transaction invokes at top level, the Compute Budget program aside.
///
/// The figure L3 judges is the whole transaction's compute. One program's
/// instructions differ from each other by orders of magnitude, and one
/// instruction costs a different amount beside an ATA creation than alone,
/// so a baseline per program judged every simulation against a band wide
/// enough for all of them. The shape is what makes two transactions'
/// figures comparable. Compute-budget instructions set limits and prices,
/// and are left out so a priority fee does not split a shape. The set is
/// hashed to keep the key short; the program and instruction stay readable,
/// and the program is the key's prefix (`<program>/`).
pub fn shape_key<'a>(
    program_id: &str,
    instruction: &str,
    top_level_programs: impl IntoIterator<Item = &'a str>,
) -> String {
    use sha2::{Digest, Sha256};
    const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
    let others: BTreeSet<&str> = top_level_programs
        .into_iter()
        .filter(|p| *p != COMPUTE_BUDGET && *p != program_id)
        .collect();
    let mut h = Sha256::new();
    h.update(b"graphite/shape/v1\0");
    for p in &others {
        h.update(p.as_bytes());
        h.update(b"\n");
    }
    let digest = h.finalize();
    format!("{program_id}/{instruction}/{}", hex::encode(&digest[..8]))
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
    if let Some(anchor) = &baseline.anchor {
        if !crate::simulation_integrity::anchor_is_valid(anchor) {
            return Err(SemanticGraphError::InvalidRecord {
                reason: "baseline anchor must be finite, with positive spreads".to_string(),
            });
        }
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
            first_manifest_unvalidated: false,
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
                first_manifest_unvalidated: false,
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
                first_manifest_unvalidated: false,
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
            first_manifest_unvalidated: false,
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

    /// A program with no existing record CAN be quarantined: the quarantine
    /// creates its first record (no evidence, forced `Unknown`), and lifting
    /// it leaves no evidence behind.
    #[test]
    fn a_program_with_no_history_can_be_quarantined_pre_emptively() {
        // This asserted `NotFound` until 2026-09-05. But the operator reaching
        // for quarantine is usually reacting to an advisory about a program
        // the gate has never seen traffic for — most seed protocols have no
        // behaviour record on a fresh instance — and refusing to block it
        // because it is "unknown" answers the wrong question.
        let mut store = SemanticGraphStore::new();
        store
            .quarantine("never-seen-program", "upstream advisory".to_string())
            .expect("blocking an unknown program is the normal case");

        let latest = store.get("never-seen-program").expect("record created");
        assert!(latest.quarantined);
        assert_eq!(latest.trust_tier, TrustTier::Unknown);
        assert_eq!(
            latest.quarantine_reason.as_deref(),
            Some("upstream advisory")
        );

        // And it can be lifted again, leaving no evidence behind to inflate a
        // tier the program never earned.
        store.lift_quarantine("never-seen-program").unwrap();
        let lifted = store.get("never-seen-program").unwrap();
        assert!(!lifted.quarantined);
        assert_eq!(lifted.trust_tier, TrustTier::Unknown);
    }

    #[test]
    fn quarantine_rejects_an_empty_program_id() {
        let mut store = SemanticGraphStore::new();
        assert!(matches!(
            store.quarantine("   ", "reason".to_string()),
            Err(SemanticGraphError::InvalidRecord { .. })
        ));
    }

    /// This asserted the OPPOSITE until 2026-09-05: that any append after a
    /// quarantine cleared it, so "a legitimate protocol upgrade after an
    /// incident is resolved" would restore the program.
    ///
    /// The flaw is who declares the incident resolved. `manifest_registry`
    /// appends on every accepted submission, and a resubmission at the same
    /// trust tier is not a promotion and so is not even P10-gated. Publishing
    /// any new version was therefore a self-service un-quarantine, available to
    /// the actor whose program had just been withdrawn from trust, with nothing
    /// checking that the new version fixed anything.
    #[test]
    fn an_upgrade_cannot_lift_its_own_quarantine() {
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
        assert_eq!(latest.version, "2.0", "the upgrade is still recorded");
        assert!(
            latest.quarantined,
            "shipping a new version must not restore a withdrawn program"
        );
        assert_eq!(latest.trust_tier, TrustTier::Unknown);
        assert_eq!(latest.quarantine_reason.as_deref(), Some("incident"));
    }

    /// The counterpart: recovery is possible, it just has to be asked for.
    #[test]
    fn lifting_a_quarantine_recomputes_the_tier_from_evidence() {
        let mut store = SemanticGraphStore::new();
        let evidence = BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 0,
            battle_tested_tx_count: 0,
            simulation_match_count: 0,
        };
        store
            .append(sample_behavior("recovering-program", "1.0", evidence))
            .unwrap();
        store
            .quarantine("recovering-program", "incident".to_string())
            .unwrap();
        store.lift_quarantine("recovering-program").unwrap();

        let latest = store.get("recovering-program").unwrap();
        assert!(!latest.quarantined);
        assert!(latest.quarantine_reason.is_none());
        // Re-derived from evidence (P7), not restored from what it used to be.
        assert_eq!(latest.trust_tier, TrustTier::OfficialManifest);
        // P4: the quarantine itself is still in history.
        let versions = store.get_all_versions("recovering-program");
        assert!(
            versions.iter().any(|b| b.quarantined),
            "lifting must not erase the quarantine record"
        );
    }

    #[test]
    fn lifting_a_quarantine_that_is_not_active_is_an_error() {
        // A no-op append to an audit trail whose value is that every entry
        // means something is worse than an error.
        let mut store = SemanticGraphStore::new();
        assert!(matches!(
            store.lift_quarantine("never-seen"),
            Err(SemanticGraphError::NotFound { .. })
        ));
        store
            .append(sample_behavior(
                "clean-program",
                "1.0",
                BehaviorEvidence {
                    has_signed_manifest: true,
                    ..Default::default()
                },
            ))
            .unwrap();
        assert!(matches!(
            store.lift_quarantine("clean-program"),
            Err(SemanticGraphError::InvalidRecord { .. })
        ));
    }

    /// Round 29 (G-3): registry evidence for a new manifest version does not
    /// wipe the program's operator-seeded volume and simulation counts.
    #[test]
    fn registry_evidence_keeps_the_programs_other_evidence() {
        let mut store = SemanticGraphStore::new();
        store
            .append(sample_behavior(
                "p",
                "1.0",
                BehaviorEvidence {
                    has_signed_manifest: true,
                    battle_tested_tx_count: 5000,
                    simulation_match_count: 7,
                    ..Default::default()
                },
            ))
            .unwrap();
        assert_eq!(store.get("p").unwrap().trust_tier, TrustTier::BattleTested);
        store
            .append_registry_evidence(sample_behavior(
                "p",
                "2.0",
                BehaviorEvidence {
                    has_signed_manifest: true,
                    ..Default::default()
                },
            ))
            .unwrap();
        let latest = store.get("p").unwrap();
        assert_eq!(latest.version, "2.0");
        assert_eq!(latest.evidence.battle_tested_tx_count, 5000);
        assert_eq!(latest.evidence.simulation_match_count, 7);
        assert_eq!(latest.trust_tier, TrustTier::BattleTested);
    }

    /// Round 29 (G-4): a restored snapshot's tiers are recomputed, not taken
    /// as written.
    #[test]
    fn restoring_a_snapshot_recomputes_every_tier() {
        let mut store = SemanticGraphStore::new();
        store
            .append(sample_behavior(
                "p",
                "1.0",
                BehaviorEvidence {
                    has_signed_manifest: true,
                    ..Default::default()
                },
            ))
            .unwrap();
        let json = store.to_json().unwrap();
        assert!(json.contains("\"OfficialManifest\""));
        let forged = json.replace("\"OfficialManifest\"", "\"BattleTested\"");
        let restored = SemanticGraphStore::from_json(&forged).unwrap();
        assert_eq!(
            restored.get("p").unwrap().trust_tier,
            TrustTier::OfficialManifest
        );
        // The same holds for a plain serde read of the snapshot.
        let raw: SemanticGraphStore = serde_json::from_str(&forged).unwrap();
        assert_eq!(
            raw.get("p").unwrap().trust_tier,
            TrustTier::OfficialManifest
        );
    }

    /// The latest-per-program index answers exactly as a reverse scan would,
    /// across interleaved programs, quarantine, and a snapshot round trip.
    #[test]
    fn the_latest_record_index_matches_a_reverse_scan() {
        let mut store = SemanticGraphStore::new();
        for i in 0..50u64 {
            let program = format!("p{}", i % 7);
            store
                .append(sample_behavior(
                    &program,
                    &i.to_string(),
                    BehaviorEvidence {
                        simulation_match_count: i,
                        ..Default::default()
                    },
                ))
                .unwrap();
        }
        store.quarantine("p3", "x".into()).unwrap();
        store.quarantine("never-seen", "y".into()).unwrap();
        let restored = SemanticGraphStore::from_json(&store.to_json().unwrap()).unwrap();
        for s in [&store, &restored] {
            for p in (0..7)
                .map(|i| format!("p{i}"))
                .chain(["never-seen".to_string()])
            {
                let scan = s.behaviors().iter().rev().find(|b| b.program_id == p);
                assert_eq!(s.get(&p), scan, "{p}");
            }
            assert!(s.get("absent").is_none());
        }
    }

    #[test]
    fn a_caller_can_never_set_quarantine_state_through_append() {
        // The fields exist on `Behavior` because they are read back out of it;
        // writing them through `append` would be a tier assignment that
        // bypasses `compute_trust_tier` (P7).
        let mut store = SemanticGraphStore::new();
        let mut b = sample_behavior(
            "sneaky",
            "1.0",
            BehaviorEvidence {
                has_signed_manifest: true,
                ..Default::default()
            },
        );
        b.quarantined = true;
        b.quarantine_reason = Some("self-declared".to_string());
        store.append(b).unwrap();

        let latest = store.get("sneaky").unwrap();
        assert!(!latest.quarantined, "quarantine is not caller-settable");
        assert_eq!(latest.trust_tier, TrustTier::OfficialManifest);
    }
}
