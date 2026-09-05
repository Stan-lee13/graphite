//! Protocol Manifest Registry — ARCHITECTURE.md 3.6 / Constitution P4, P7,
//! P10, P11. Design: see docs/phase2-plan.md "G5 Independence Check — DESIGN".
//!
//! The Manifest Registry lets protocols be the source of truth about
//! themselves: community members submit manifests, and only a REGISTERED,
//! reputation-bearing reviewer's valid signature moves a manifest onto the
//! Semantic Graph at a COMPUTED trust tier.
//!
//! Honest model:
//! - **Tier is computed, never asserted (P7).** Submissions contribute
//!   EVIDENCE (`has_signed_manifest`, independent attestation count);
//!   `compute_trust_tier` derives the tier. The store's `append` recomputes
//!   it too — a submission can never name its own tier.
//! - **G5 independence:** `community_verified_count` counts only DISTINCT
//!   registered reviewers (reputation ≥ `MIN_REVIEWER_REPUTATION`) whose
//!   attestation signature verifies over the submission's content hash —
//!   one attestation per (program, version) per reviewer. Duplicate, invalid,
//!   and unregistered attestations are dropped.
//! - **Anonymous signing is worthless (P7):** a valid ed25519 signature by an
//!   UNREGISTERED key earns no tier. A signature by a low-reputation
//!   registered key is rejected outright.
//! - **Append-only (P4):** accepted submissions are recorded in an append-only
//!   log with version lineage (`previous_version_ref`); the Semantic Graph
//!   append is likewise append-only.
//! - **P10 gate:** a submission that would PROMOTE the program's trust tier
//!   requires a passing regression run over that program's fixtures. The
//!   engine runs the replay ITSELF (`replay_corpus_for_program`) against the
//!   supplied corpus — a caller can never hand it a fabricated "passing" run.
//! - **P11:** trust is keyed by the exact `programId` string — no fuzzy match.
//!
//! Registry submissions reach at most Tier 4 (`CommunityVerified`): Tier 5
//! (`BattleTested`) requires 1,000+ battle-tested transactions, which are
//! earned by real usage, never self-attested through the registry.

use crate::confidence_engine::TrustTier;
use crate::manifest::ProtocolManifest;
use crate::regression_engine::{
    decide_promotion, replay_corpus_for_program, PromotionDecision, RegressionCorpus,
};
use crate::semantic_graph_store::{
    compute_trust_tier, Behavior, BehaviorEvidence, SemanticGraphStore,
};
use crate::verification::GraphiteCore;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Minimum demonstrated reputation for a reviewer's signature/attestation to
/// count (G5). Operational parameter, not a security boundary on its own.
pub const MIN_REVIEWER_REPUTATION: u64 = 100;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("signature is invalid or malformed: {0}")]
    InvalidSignature(String),
    #[error("signer is not a registered reviewer: {0}")]
    UnregisteredReviewer(String),
    #[error("reviewer reputation {reputation} below minimum {min}")]
    LowReputation { reputation: u64, min: u64 },
    #[error("program_id cannot be empty or whitespace-only")]
    EmptyProgramId,
    #[error("promotion blocked by P10 regression gate: {0}")]
    RegressionGateBlocked(String),
    #[error("reviewer pubkey cannot be empty or whitespace-only")]
    InvalidReviewerPubkey,
    #[error("submission carries no verifiable evidence (no valid signature and no qualifying attestation)")]
    NoEvidence,
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
}

/// Outcome of a registry submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryDecision {
    Accepted {
        trust_tier: TrustTier,
        version_label: String,
    },
    Rejected {
        reason: String,
    },
}

/// A registered reviewer identity (G5): pubkey + demonstrated reputation.
/// Registration is an operator API in Phase 2; on-chain stake lookup is
/// Phase 3. The engine stores reviewers as these (never bare strings), so the
/// identity/reputation pair is the only reviewer shape in the system.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegistryReviewer {
    pub pubkey: String,
    /// Demonstrated stake/reputation score (operator-verified).
    pub reputation_score: u64,
}

/// An independent reviewer attestation over a submission's content hash.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReviewerAttestation {
    pub reviewer_pubkey: String,
    /// hex-encoded ed25519 signature over the content hash.
    pub signature_hex: String,
}

/// A community manifest submission. `signer_pubkey`/`signature_hex` are the
/// submitter's own signature; `attestations` are independent reviewers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ManifestSubmission {
    pub manifest: ProtocolManifest,
    pub signer_pubkey: Option<String>,
    pub signature_hex: Option<String>,
    #[serde(default)]
    pub attestations: Vec<ReviewerAttestation>,
}

impl ManifestSubmission {
    /// The deterministic signing message: sha256 of the canonical manifest
    /// JSON. Signatures and attestations verify over this.
    pub fn content_hash(&self) -> String {
        Self::content_hash_of(&self.manifest)
    }

    fn content_hash_of(manifest: &ProtocolManifest) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_string(manifest).expect("manifest is serializable");
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// One accepted submission in the append-only acceptance log (P4).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RegistryRecord {
    pub program_id: String,
    pub version_label: String,
    pub previous_version_ref: Option<String>,
    pub content_hash: String,
    pub trust_tier: TrustTier,
    /// "signed" (registered-reporter signature) or "community" (attestations).
    pub source: String,
    /// The full accepted manifest, retained so community-accepted manifests
    /// can be merged into the runtime verification registry (C53). `None`
    /// for records persisted before this field existed (serde default).
    #[serde(default)]
    pub manifest: Option<ProtocolManifest>,
}

/// The community Manifest Registry engine.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ManifestRegistryEngine {
    /// Registered reviewers: pubkey → identity + demonstrated reputation (G5).
    reviewers: HashMap<String, RegistryReviewer>,
    /// Append-only acceptance log with version lineage (P4).
    records: Vec<RegistryRecord>,
}

impl ManifestRegistryEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a reviewer identity with a demonstrated reputation score.
    /// Operator API (Phase 2: operator-verified stake/GitHub claim).
    pub fn register_reviewer(
        &mut self,
        pubkey: &str,
        reputation_score: u64,
    ) -> Result<(), RegistryError> {
        if pubkey.trim().is_empty() {
            return Err(RegistryError::InvalidReviewerPubkey);
        }
        self.reviewers.insert(
            pubkey.to_string(),
            RegistryReviewer {
                pubkey: pubkey.to_string(),
                reputation_score,
            },
        );
        Ok(())
    }

    pub fn reviewer_reputation(&self, pubkey: &str) -> Option<u64> {
        self.reviewers.get(pubkey).map(|r| r.reputation_score)
    }

    pub fn reviewers(&self) -> &HashMap<String, RegistryReviewer> {
        &self.reviewers
    }

    /// Append-only acceptance history (P4).
    pub fn records(&self) -> &[RegistryRecord] {
        &self.records
    }

    /// Last accepted record for a program (version lineage head).
    pub fn last_accepted(&self, program_id: &str) -> Option<&RegistryRecord> {
        self.records
            .iter()
            .rev()
            .find(|r| r.program_id == program_id)
    }

    /// Accepted manifests retained in the acceptance log, in acceptance
    /// order. Records persisted before the `manifest` field existed (serde
    /// default `None`) are skipped. The verification core merges these into
    /// its runtime registry (C53) so community-accepted protocols actually
    /// resolve at verification time, not just in the dashboard.
    pub fn accepted_manifests(&self) -> impl Iterator<Item = &ProtocolManifest> {
        self.records.iter().filter_map(|r| r.manifest.as_ref())
    }

    /// Submit a community manifest.
    ///
    /// `regression` is required only when the submission would PROMOTE the
    /// program's current trust tier (P10): the engine runs the replay itself
    /// over the supplied corpus, so a fabricated "passing" run is impossible.
    pub fn submit(
        &mut self,
        store: &mut SemanticGraphStore,
        submission: ManifestSubmission,
        regression: Option<(&RegressionCorpus, &GraphiteCore)>,
    ) -> Result<RegistryDecision, RegistryError> {
        let program_id = submission.manifest.protocol.program_id.clone();
        if program_id.trim().is_empty() {
            return Err(RegistryError::EmptyProgramId);
        }
        // Schema validation — mirror the runtime loader: a manifest the loader
        // would refuse must not be enshrined at an earned tier.
        Self::validate_manifest(&submission.manifest)?;
        let content_hash = submission.content_hash();
        let version_label = submission.manifest.version.label.clone();

        // Evidence from the submission — P7: tier derived, never asserted.
        let evidence = self.evidence_from_submission(&submission, &content_hash)?;
        if !evidence.has_signed_manifest && evidence.community_verified_count == 0 {
            return Err(RegistryError::NoEvidence);
        }
        let tier = compute_trust_tier(&evidence);

        // P10 gate: promotion requires the ENGINE'S OWN replay over this
        // program's fixtures to pass (fabricated runs are impossible).
        let current_tier = store.get(&program_id).map(|b| b.trust_tier);
        let is_promotion =
            current_tier.is_some_and(|current| tier_rank(&tier) > tier_rank(&current));
        if is_promotion {
            let (corpus, core) = regression.ok_or_else(|| {
                RegistryError::RegressionGateBlocked(
                    "no regression corpus supplied for a tier promotion".to_string(),
                )
            })?;
            let run = replay_corpus_for_program(core, corpus, &program_id);
            match decide_promotion(&run) {
                PromotionDecision::Promote => {}
                PromotionDecision::Block { reason } => {
                    return Err(RegistryError::RegressionGateBlocked(reason));
                }
            }
        }

        // P4: append to the Semantic Graph (append recomputes the tier) and to
        // the acceptance log with version lineage.
        let expected_state_changes: Vec<String> = submission
            .manifest
            .instructions
            .iter()
            .flat_map(|ix| ix.expected_state_changes.iter().cloned())
            .collect();
        let allowed_cpis: Vec<String> = submission
            .manifest
            .instructions
            .iter()
            .flat_map(|ix| ix.allowed_cpis.iter().cloned())
            .collect();
        store
            .append(Behavior {
                program_id: program_id.clone(),
                version: version_label.clone(),
                expected_state_changes,
                allowed_cpis,
                trust_tier: TrustTier::Unknown, // ignored — recomputed by append (P7)
                evidence: evidence.clone(),
                quarantined: false,
                quarantine_reason: None,
            })
            // append's only error is an empty program_id, which was rejected
            // above (EmptyProgramId) — unreachable here.
            .expect("append cannot fail after program_id validation");

        let previous_version_ref = self
            .last_accepted(&program_id)
            .map(|r| r.version_label.clone())
            .or_else(|| submission.manifest.version.previous_version_ref.clone());
        self.records.push(RegistryRecord {
            program_id: program_id.clone(),
            version_label: version_label.clone(),
            previous_version_ref,
            content_hash,
            trust_tier: tier,
            source: if evidence.has_signed_manifest {
                "signed".to_string()
            } else {
                "community".to_string()
            },
            manifest: Some(submission.manifest.clone()),
        });

        Ok(RegistryDecision::Accepted {
            trust_tier: tier,
            version_label,
        })
    }

    /// Validate the manifest surface (mirrors `ManifestRegistry`'s loader
    /// rejection rules: at least one instruction, each with a discriminator).
    fn validate_manifest(manifest: &ProtocolManifest) -> Result<(), RegistryError> {
        if manifest.instructions.is_empty() {
            return Err(RegistryError::InvalidManifest(
                "manifest must declare at least one instruction".to_string(),
            ));
        }

        // Resource-exhaustion guard: a community submission must never be able
        // to carry an unbounded instruction/account/list payload through the
        // hashing, serialization, and graph-storage path (memory + CPU DoS).
        const MAX_INSTRUCTIONS: usize = 512;
        const MAX_ACCOUNTS_PER_INSTRUCTION: usize = 256;
        const MAX_FIELD_CHARS: usize = 128;
        const MAX_LIST_ITEMS: usize = 64;
        if manifest.instructions.len() > MAX_INSTRUCTIONS {
            return Err(RegistryError::InvalidManifest(format!(
                "manifest declares {} instructions (cap {MAX_INSTRUCTIONS}) — resource-exhaustion guard",
                manifest.instructions.len()
            )));
        }
        // Discriminator-length decision (certification item): matching is
        // PREFIX-based (`input.starts_with(manifest_disc)`) because Solana
        // instruction selectors are the LEADING bytes of instruction data —
        // 2 hex chars (1 byte, SPL Token/Token-2022), 8 hex chars (4 bytes,
        // System u32 LE), 16 hex chars (8 bytes, Anchor-style). An input like
        // "0900000000000000" MUST match manifest "09". Prefix matching is
        // unambiguous iff no two instructions of a program have one
        // discriminator as a proper prefix of another; such manifests are
        // rejected here (fail-closed — an ambiguous selector could route an
        // instruction to the wrong security rules).
        for i in 0..manifest.instructions.len() {
            for j in (i + 1)..manifest.instructions.len() {
                let a = manifest.instructions[i].discriminator.to_lowercase();
                let b = manifest.instructions[j].discriminator.to_lowercase();
                let ambiguous =
                    !a.is_empty() && !b.is_empty() && (a.starts_with(&b) || b.starts_with(&a));
                if ambiguous {
                    return Err(RegistryError::InvalidManifest(format!(
                        "discriminator ambiguity: '{}' ({}) and '{}' ({}) are prefix-related — prefix matching would be ambiguous; use distinct-width selectors",
                        manifest.instructions[i].name,
                        a,
                        manifest.instructions[j].name,
                        b
                    )));
                }
            }
        }
        for ix in &manifest.instructions {
            if ix.name.chars().count() > MAX_FIELD_CHARS {
                return Err(RegistryError::InvalidManifest(format!(
                    "instruction name exceeds {MAX_FIELD_CHARS} chars"
                )));
            }
            if ix.accounts.len() > MAX_ACCOUNTS_PER_INSTRUCTION {
                return Err(RegistryError::InvalidManifest(format!(
                    "instruction '{}' declares {} accounts (cap {MAX_ACCOUNTS_PER_INSTRUCTION}) — resource-exhaustion guard",
                    ix.name,
                    ix.accounts.len()
                )));
            }
            if ix.allowed_cpis.len() > MAX_LIST_ITEMS
                || ix.expected_state_changes.len() > MAX_LIST_ITEMS
                || ix.risk_rules.len() > MAX_LIST_ITEMS
            {
                return Err(RegistryError::InvalidManifest(format!(
                    "instruction '{}' exceeds list cap {MAX_LIST_ITEMS} (allowed_cpis/state_changes/risk_rules) — resource-exhaustion guard",
                    ix.name
                )));
            }
            // Per-string length cap as well: a single oversized list entry
            // would otherwise pass the count cap. Overall worst case stays
            // bounded (~instructions × items × chars).
            for list in [&ix.allowed_cpis, &ix.expected_state_changes, &ix.risk_rules] {
                if list.iter().any(|s| s.chars().count() > MAX_FIELD_CHARS) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "instruction '{}' has a list entry exceeding {MAX_FIELD_CHARS} chars — resource-exhaustion guard",
                        ix.name
                    )));
                }
            }
            for acc in &ix.accounts {
                if acc.pda_seeds.len() > MAX_LIST_ITEMS {
                    return Err(RegistryError::InvalidManifest(format!(
                        "account '{}' exceeds {MAX_LIST_ITEMS} pda seeds — resource-exhaustion guard",
                        acc.name
                    )));
                }
            }
            if ix.discriminator.trim().is_empty() {
                // Deliberately STRICTER than the runtime loader, which allows
                // empty discriminators for raw-UTF-8-data programs (e.g. the
                // Memo program). Those programs cannot be enshrined via
                // registry submission — they must be onboarded through the
                // seed registry. Fail-closed, never silently downgraded.
                return Err(RegistryError::InvalidManifest(format!(
                    "instruction '{}' has no discriminator — the registry is stricter than the runtime loader: raw-UTF-8-data programs (e.g. Memo) must be onboarded through the seed registry, not community submission",
                    ix.name
                )));
            }
        }
        Ok(())
    }

    /// Derive BehaviorEvidence from a submission (G5 + P7).
    fn evidence_from_submission(
        &self,
        submission: &ManifestSubmission,
        content_hash: &str,
    ) -> Result<BehaviorEvidence, RegistryError> {
        let mut evidence = BehaviorEvidence::default();

        // signer_pubkey and signature_hex must be provided together — a
        // partial pair is a malformed submission, not a silent no-op.
        match (&submission.signer_pubkey, &submission.signature_hex) {
            (None, None) => {}
            (Some(_), Some(_)) => {}
            _ => {
                return Err(RegistryError::InvalidSignature(
                    "signer_pubkey and signature_hex must be provided together".to_string(),
                ));
            }
        }

        // 1. Submitter signature — only registered reviewers with sufficient
        // reputation count (P7, G5).
        if let (Some(signer), Some(sig)) = (&submission.signer_pubkey, &submission.signature_hex) {
            if !Self::verify_signature(signer, sig, content_hash) {
                return Err(RegistryError::InvalidSignature(
                    "signer signature does not verify".to_string(),
                ));
            }
            let reputation = self
                .reviewer_reputation(signer)
                .ok_or_else(|| RegistryError::UnregisteredReviewer(signer.clone()))?;
            if reputation < MIN_REVIEWER_REPUTATION {
                return Err(RegistryError::LowReputation {
                    reputation,
                    min: MIN_REVIEWER_REPUTATION,
                });
            }
            evidence.has_signed_manifest = true;
        }

        // 2. Independent attestations (G5): distinct registered reviewers with
        // valid signatures only; one attestation per reviewer per content.
        let mut counted: HashSet<String> = HashSet::new();
        for attestation in &submission.attestations {
            let Some(reputation) = self.reviewer_reputation(&attestation.reviewer_pubkey) else {
                continue; // unregistered reviewer contributes nothing
            };
            if reputation < MIN_REVIEWER_REPUTATION {
                continue;
            }
            if !Self::verify_signature(
                &attestation.reviewer_pubkey,
                &attestation.signature_hex,
                content_hash,
            ) {
                continue; // invalid attestation is dropped, not an error
            }
            if !counted.insert(attestation.reviewer_pubkey.clone()) {
                continue; // one attestation per reviewer per content
            }
            evidence.community_verified_count += 1;
        }

        Ok(evidence)
    }

    /// Verify an ed25519 signature over the content-hash string.
    fn verify_signature(pubkey_b58: &str, signature_hex: &str, content_hash: &str) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};
        let Ok(decoded) = bs58::decode(pubkey_b58).into_vec() else {
            return false;
        };
        let Ok(pk_bytes) = <[u8; 32]>::try_from(decoded.as_slice()) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(signature_hex) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let Ok(pk) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        pk.verify_strict(content_hash.as_bytes(), &sig).is_ok()
    }

    /// Durability snapshot (same pattern as SemanticGraphStore).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Ordinal rank of a trust tier for promotion comparison (the enum has no
/// Ord derive; this is the single source of tier ordering here).
fn tier_rank(tier: &TrustTier) -> u8 {
    match tier {
        TrustTier::Unknown => 0,
        TrustTier::HeuristicInferred => 1,
        TrustTier::OfficialManifest => 2,
        TrustTier::SimulationValidated => 3,
        TrustTier::CommunityVerified => 4,
        TrustTier::BattleTested => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo};
    use crate::policy_engine::WalletProfile;
    use crate::regression_engine::{RegressionCorpus, RegressionFixture};
    use crate::verification::ProposedIntent;
    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministic signing key from fixed bytes (no RNG needed).
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey_b58(key: &SigningKey) -> String {
        bs58::encode(key.verifying_key().to_bytes()).into_string()
    }

    fn sign(key: &SigningKey, content_hash: &str) -> String {
        hex::encode(key.sign(content_hash.as_bytes()).to_bytes())
    }

    fn manifest(program_id: &str, name: &str, version: &str) -> ProtocolManifest {
        ProtocolManifest {
            graphite_manifest_version: "1.0".to_string(),
            protocol: ProtocolInfo {
                name: name.to_string(),
                program_id: program_id.to_string(),
                website: String::new(),
                github: String::new(),
                category: String::new(),
            },
            version: ManifestVersion {
                label: version.to_string(),
                effective_from_slot: 0,
                previous_version_ref: None,
            },
            // A registry manifest must declare at least one instruction with a
            // discriminator (mirrors the runtime loader's schema validation).
            instructions: vec![InstructionDef {
                name: "TestOp".to_string(),
                discriminator: "01".to_string(),
                accounts: vec![],
                expected_state_changes: vec!["debits accounts.from".to_string()],
                allowed_cpis: vec![],
                risk_rules: vec![],
                variable_accounts: false,
                risk_class: String::new(),
            }],
            trust_tier: String::new(),
        }
    }

    fn sign_manifest(m: ProtocolManifest, signer: &SigningKey) -> ManifestSubmission {
        let sub = ManifestSubmission {
            manifest: m,
            signer_pubkey: Some(pubkey_b58(signer)),
            signature_hex: None, // filled after content_hash is known
            attestations: vec![],
        };
        let hash = sub.content_hash();
        ManifestSubmission {
            signature_hex: Some(sign(signer, &hash)),
            ..sub
        }
    }

    fn signed_submission(program: &str, version: &str, signer: &SigningKey) -> ManifestSubmission {
        sign_manifest(manifest(program, "Test Protocol", version), signer)
    }

    #[test]
    fn ambiguous_prefix_discriminators_are_rejected() {
        // Certification decision: prefix matching is only safe when no two
        // instructions have prefix-related discriminators. A manifest that
        // declares both "09" and "0900" must be rejected at submission.
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(2);
        let signer_b58 = pubkey_b58(&signer);
        engine.register_reviewer(&signer_b58, 1000).unwrap();

        let mut m = manifest(
            "Prog1111111111111111111111111111111111",
            "Ambiguous",
            "v1.0",
        );
        let mut second = m.instructions[0].clone();
        second.name = "SecondOp".to_string();
        second.discriminator = "0100".to_string(); // "01" is a proper prefix of "0100"
        m.instructions.push(second);
        let submission = sign_manifest(m, &signer);
        assert!(
            matches!(
                engine.submit(&mut store, submission, None),
                Err(RegistryError::InvalidManifest(reason)) if reason.contains("discriminator ambiguity")
            ),
            "prefix-ambiguous discriminators must be rejected"
        );
    }

    fn make_fixture_input(
        program: &str,
        disc: &str,
        intent: &str,
        cpi: &[&str],
        accounts: &[&str],
    ) -> crate::verification::VerificationInput {
        crate::verification::VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: intent.to_string(),
                raw_natural_language: "test".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: program.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: disc.to_string(),
            account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
            instruction_data: None,
            cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
            wallet_profile: WalletProfile::Custom {
                min_confidence: 0.40,
                min_trust_tier: TrustTier::OfficialManifest,
            },
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 150,
            account_writes: 2,
            cpi_hops: cpi.len() as u32,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
        }
    }

    #[test]
    fn valid_registered_reviewer_signature_earns_official_manifest() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(1);
        let signer_b58 = pubkey_b58(&signer);
        engine.register_reviewer(&signer_b58, 1000).unwrap();

        let submission = signed_submission(
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "v1.0",
            &signer,
        );
        let decision = engine.submit(&mut store, submission, None).unwrap();
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::OfficialManifest,
                version_label: "v1.0".to_string(),
            }
        );
        // P7: the graph record's tier matches, computed not asserted.
        let record = store
            .get("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
            .unwrap();
        assert_eq!(record.trust_tier, TrustTier::OfficialManifest);
        assert!(record.evidence.has_signed_manifest);
    }

    #[test]
    fn registry_rejects_resource_exhaustion_manifest() {
        // 1000 instructions (cap 512) must be rejected BEFORE any hashing or
        // signing work — a clean resource-exhaustion guard, not an OOM.
        let mut m = manifest("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", "Huge", "v1");
        m.instructions = (0..1000)
            .map(|i| InstructionDef {
                name: format!("op{i}"),
                discriminator: "01".to_string(),
                accounts: vec![],
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                risk_rules: vec![],
                variable_accounts: false,
                risk_class: String::new(),
            })
            .collect();
        let err = ManifestRegistryEngine::validate_manifest(&m).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("resource-exhaustion guard"),
            "expected cap error, got: {msg}"
        );

        // 300 accounts on one instruction (cap 256) is rejected too.
        let mut m2 = manifest("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", "Huge2", "v1");
        m2.instructions[0].accounts = (0..300)
            .map(|i| AccountRoleDef {
                name: format!("acc{i}"),
                role: "readonly".to_string(),
                is_writable: false,
                is_signer: false,
                pda_seeds: vec![],
                expected_address: vec![],
            })
            .collect();
        let err2 = ManifestRegistryEngine::validate_manifest(&m2).unwrap_err();
        assert!(
            format!("{err2:?}").contains("resource-exhaustion guard"),
            "expected account-cap error"
        );

        // A normal manifest still passes — the caps must not false-positive.
        let ok = ManifestRegistryEngine::validate_manifest(&manifest(
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "Ok",
            "v1",
        ));
        assert!(ok.is_ok());
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(2);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        let mut submission = signed_submission(
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "v1.0",
            &signer,
        );
        // Tamper with the manifest AFTER signing — the content hash changes.
        submission.manifest.protocol.name = "Evil Renamed Protocol".to_string();
        let err = engine.submit(&mut store, submission, None).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSignature(_)));
        assert!(store
            .get("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .is_none());
    }

    #[test]
    fn anonymous_signature_earns_nothing() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        // Signer is NOT registered — valid signature, no reputation.
        let signer = key(3);
        let submission = signed_submission(
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "v1.0",
            &signer,
        );
        let err = engine.submit(&mut store, submission, None).unwrap_err();
        assert!(matches!(err, RegistryError::UnregisteredReviewer(_)));
    }

    #[test]
    fn low_reputation_registered_reviewer_is_rejected() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(4);
        let signer_b58 = pubkey_b58(&signer);
        engine
            .register_reviewer(&signer_b58, MIN_REVIEWER_REPUTATION - 1)
            .unwrap();

        let submission = signed_submission(
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
            "v1.0",
            &signer,
        );
        let err = engine.submit(&mut store, submission, None).unwrap_err();
        assert!(matches!(err, RegistryError::LowReputation { .. }));
    }

    #[test]
    fn empty_program_id_is_rejected_p11() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(5);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let submission = signed_submission("", "v1.0", &signer);
        assert_eq!(
            engine.submit(&mut store, submission, None).unwrap_err(),
            RegistryError::EmptyProgramId
        );
    }

    #[test]
    fn unsigned_unattested_submission_is_rejected_no_evidence() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let submission = ManifestSubmission {
            manifest: manifest(
                "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
                "Squads",
                "v1.0",
            ),
            signer_pubkey: None,
            signature_hex: None,
            attestations: vec![],
        };
        assert_eq!(
            engine.submit(&mut store, submission, None).unwrap_err(),
            RegistryError::NoEvidence
        );
    }

    #[test]
    fn g5_attestations_count_only_distinct_registered_reviewers() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        // Three registered reviewers.
        let a = key(10);
        let b = key(11);
        let c = key(12);
        engine.register_reviewer(&pubkey_b58(&a), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&b), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&c), 1000).unwrap();
        // One unregistered attacker identity.
        let attacker = key(13);

        let m = manifest(
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
            "Meteora",
            "v2.0",
        );
        let mut submission = ManifestSubmission {
            manifest: m,
            signer_pubkey: None,
            signature_hex: None,
            attestations: vec![],
        };
        let hash = submission.content_hash();
        // Valid attestations: a, b, and a duplicate of a (counts once),
        // an invalid signature (c signed the wrong message), and the
        // unregistered attacker (dropped).
        submission.attestations = vec![
            ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(&a),
                signature_hex: sign(&a, &hash),
            },
            ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(&b),
                signature_hex: sign(&b, &hash),
            },
            ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(&a),
                signature_hex: sign(&a, &hash),
            },
            ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(&c),
                signature_hex: sign(&c, "tampered-hash"),
            },
            ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(&attacker),
                signature_hex: sign(&attacker, &hash),
            },
        ];

        let decision = engine.submit(&mut store, submission, None).unwrap();
        // 2 distinct registered reviewers with valid attestations → Tier 4.
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::CommunityVerified,
                version_label: "v2.0".to_string(),
            }
        );
        let record = store
            .get("LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo")
            .unwrap();
        assert_eq!(record.evidence.community_verified_count, 2);
    }
    fn seed_heuristic_inferred(store: &mut SemanticGraphStore, program_id: &str) {
        store
            .append(Behavior {
                program_id: program_id.to_string(),
                version: "v1.0".to_string(),
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                trust_tier: TrustTier::Unknown,
                evidence: BehaviorEvidence {
                    has_signed_manifest: false,
                    community_verified_count: 0,
                    battle_tested_tx_count: 1,
                    simulation_match_count: 0,
                },
                quarantined: false,
                quarantine_reason: None,
            })
            .unwrap();
    }

    const SYSTEM: &str = "11111111111111111111111111111111";
    const ACCT_A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const ACCT_B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

    #[test]
    fn p10_gate_blocks_promotion_when_engine_replay_fails() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(20);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        // System already on the graph at Tier 1 (HeuristicInferred).
        seed_heuristic_inferred(&mut store, SYSTEM);
        assert_eq!(
            store.get(SYSTEM).unwrap().trust_tier,
            TrustTier::HeuristicInferred
        );

        // A signed v2.0 submission would promote to Tier 2 — but the engine's
        // own replay over THIS program's corpus fails (fixture recorded as
        // approved, yet replays as blocked: System + "stake" intent).
        let submission = signed_submission(SYSTEM, "v2.0", &signer);
        let mut corpus = RegressionCorpus::new();
        corpus.add_fixture(RegressionFixture::new(
            make_fixture_input(SYSTEM, "02000000", "stake", &[], &[ACCT_A, ACCT_B]),
            true, // recorded approved — but it will NOT verify as approved
            "manual",
        ));
        let core = GraphiteCore::new();

        let err = engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap_err();
        assert!(matches!(err, RegistryError::RegressionGateBlocked(_)));
        // Nothing was appended (P10 block is pre-append).
        assert_eq!(store.get_all_versions(SYSTEM).len(), 1);
    }

    #[test]
    fn p10_gate_allows_promotion_when_engine_replay_passes() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(21);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        seed_heuristic_inferred(&mut store, SYSTEM);

        let submission = signed_submission(SYSTEM, "v2.0", &signer);
        let mut corpus = RegressionCorpus::new();
        corpus.add_fixture(RegressionFixture::new(
            make_fixture_input(SYSTEM, "02000000", "transfer", &[], &[ACCT_A, ACCT_B]),
            true,
            "manual",
        ));
        let core = GraphiteCore::new();

        let decision = engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap();
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::OfficialManifest,
                version_label: "v2.0".to_string(),
            }
        );
    }

    #[test]
    fn p10_gate_blocks_promotion_with_no_fixtures_for_program() {
        // A promotion with NO recorded fixtures for the program must block
        // (P10: no recorded evidence, no promotion) — and the engine runs the
        // replay itself, so an empty per-program run cannot be faked.
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(23);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        seed_heuristic_inferred(&mut store, SYSTEM);

        let submission = signed_submission(SYSTEM, "v2.0", &signer);
        let empty_corpus = RegressionCorpus::new(); // no fixtures for SYSTEM
        let core = GraphiteCore::new();
        let err = engine
            .submit(&mut store, submission, Some((&empty_corpus, &core)))
            .unwrap_err();
        assert!(matches!(err, RegistryError::RegressionGateBlocked(_)));
    }

    #[test]
    fn self_asserted_trust_tier_in_manifest_is_ignored_p7() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(60);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        // The signed manifest claims BattleTested — the engine must ignore it
        // and derive the tier from evidence (P7).
        let mut m = manifest(SYSTEM, "System Program", "v1.0");
        m.trust_tier = "BattleTested".to_string();
        let submission = sign_manifest(m, &signer);

        let decision = engine.submit(&mut store, submission, None).unwrap();
        assert!(matches!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::OfficialManifest,
                ..
            }
        ));
        assert_eq!(
            store.get(SYSTEM).unwrap().trust_tier,
            TrustTier::OfficialManifest
        );
    }

    #[test]
    fn partial_signature_pair_is_rejected() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(61);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        let sub = ManifestSubmission {
            manifest: manifest(SYSTEM, "System Program", "v1.0"),
            signer_pubkey: Some(pubkey_b58(&signer)),
            signature_hex: None, // missing signature — malformed pair
            attestations: vec![],
        };
        let err = engine.submit(&mut store, sub, None).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSignature(_)));
    }

    #[test]
    fn empty_instructions_manifest_is_rejected() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(62);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        let mut m = manifest(SYSTEM, "System Program", "v1.0");
        m.instructions = vec![];
        let sub = sign_manifest(m, &signer);
        let err = engine.submit(&mut store, sub, None).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidManifest(_)));
    }

    #[test]
    fn new_program_acceptance_needs_no_regression_gate() {
        // A brand-new program (no prior record) is not a promotion — accepted
        // with a signed submission and no regression run.
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(22);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let submission = signed_submission(
            "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
            "v1.0",
            &signer,
        );
        let decision = engine.submit(&mut store, submission, None).unwrap();
        assert!(matches!(decision, RegistryDecision::Accepted { .. }));
    }

    #[test]
    fn version_lineage_is_append_only_and_linked() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(30);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        let program = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
        engine
            .submit(
                &mut store,
                signed_submission(program, "v1.0", &signer),
                None,
            )
            .unwrap();
        engine
            .submit(
                &mut store,
                signed_submission(program, "v2.0", &signer),
                None,
            )
            .unwrap();

        // P4: both versions on the graph, append-only.
        let versions = store.get_all_versions(program);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "v1.0");
        assert_eq!(versions[1].version, "v2.0");

        // Lineage: v2.0's previous_version_ref points at v1.0.
        let records = engine.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].previous_version_ref.as_deref(), Some("v1.0"));
        assert_eq!(records[1].version_label, "v2.0");
    }

    #[test]
    fn registration_rejects_empty_pubkey() {
        let mut engine = ManifestRegistryEngine::new();
        assert!(engine.register_reviewer("", 1000).is_err());
        assert!(engine.register_reviewer("   ", 1000).is_err());
    }

    #[test]
    fn engine_snapshot_roundtrips() {
        let mut engine = ManifestRegistryEngine::new();
        engine
            .register_reviewer(&pubkey_b58(&key(40)), 500)
            .unwrap();
        let json = engine.to_json().unwrap();
        let restored = ManifestRegistryEngine::from_json(&json).unwrap();
        assert_eq!(restored.reviewers(), engine.reviewers());
    }

    #[test]
    fn deterministic_same_submission_same_decision() {
        let mut engine = ManifestRegistryEngine::new();
        let signer = key(50);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let program = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";

        let mut store_a = SemanticGraphStore::new();
        let mut store_b = SemanticGraphStore::new();
        let d1 = engine
            .submit(
                &mut store_a,
                signed_submission(program, "v1.0", &signer),
                None,
            )
            .unwrap();
        let d2 = engine
            .submit(
                &mut store_b,
                signed_submission(program, "v1.0", &signer),
                None,
            )
            .unwrap();
        assert_eq!(d1, d2, "same submission ⇒ same decision (P2)");
    }

    /// C53: an accepted submission must persist its full manifest so the
    /// verification core can merge it into the runtime registry (Finding 3 —
    /// the registry was previously only a dashboard, never wired into
    /// verification). The snapshot round-trip must carry the manifest.
    #[test]
    fn accepted_manifest_survives_snapshot_roundtrip() {
        let mut engine = ManifestRegistryEngine::new();
        let signer = key(60);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let program = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
        let mut store = SemanticGraphStore::new();
        engine
            .submit(
                &mut store,
                signed_submission(program, "v1.0", &signer),
                None,
            )
            .unwrap();

        // Accepted manifests must be visible before and after the round-trip.
        assert_eq!(engine.accepted_manifests().count(), 1);
        assert_eq!(
            engine
                .accepted_manifests()
                .next()
                .unwrap()
                .protocol
                .program_id,
            program
        );

        let json = engine.to_json().unwrap();
        let restored = ManifestRegistryEngine::from_json(&json).unwrap();
        assert_eq!(restored.accepted_manifests().count(), 1);
        assert_eq!(
            restored
                .accepted_manifests()
                .next()
                .unwrap()
                .protocol
                .program_id,
            program
        );
    }

    /// C53 end-to-end: a community-accepted manifest merges into a fresh
    /// GraphiteCore's runtime registry (seed-wins: the seed manifest for the
    /// same program is NOT overridden), and verification resolves the
    /// community-accepted program as a known protocol — proving the registry
    /// now feeds the verification path, not just the dashboard.
    #[test]
    fn accepted_community_manifest_reaches_verification_registry() {
        use crate::manifest::load_seed_manifests;

        // A program with a seed manifest (Jupiter V6) and a real mainnet
        // program with NO seed manifest (CLINKSINK drainer — a valid 32-byte
        // base58 pubkey, never seed-manifested).
        let seed_program = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
        let community_program = "4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa";

        let mut engine = ManifestRegistryEngine::new();
        let signer = key(61);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let mut store = SemanticGraphStore::new();
        // Submit a manifest for the community program AND an attempted
        // override of the seed program.
        engine
            .submit(
                &mut store,
                signed_submission(community_program, "v1.0", &signer),
                None,
            )
            .unwrap();
        engine
            .submit(
                &mut store,
                signed_submission(seed_program, "v1.0", &signer),
                None,
            )
            .unwrap();

        let mut registry = load_seed_manifests();
        let seed_disc = registry
            .get(seed_program)
            .expect("seed manifest present")
            .instructions
            .first()
            .map(|i| i.discriminator.clone());

        let merged =
            registry.merge_community(&engine.accepted_manifests().cloned().collect::<Vec<_>>());
        // Only the brand-new community program merges; the seed program's
        // manifest is untouched (seed-wins).
        assert_eq!(merged, 1);
        assert!(registry.get(community_program).is_some());
        let seed = registry.get(seed_program).expect("seed still present");
        assert_eq!(
            seed.instructions.first().map(|i| i.discriminator.clone()),
            seed_disc,
            "community submission must NOT override the seed manifest"
        );

        // End-to-end: the merged manifest is visible through a GraphiteCore
        // that merges the engine, and verification resolves the community
        // program as a known protocol (manifest_found = true).
        let mut core = crate::verification::GraphiteCore::new();
        let n = core.merge_community_manifests(&engine);
        assert_eq!(n, 1, "one new community program merges into the core");
        let result = core
            .verify(&make_fixture_input(
                community_program,
                "01",
                "transfer",
                &[],
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
            ))
            .unwrap();
        assert!(
            result.manifest_found,
            "community-accepted program must resolve as a known protocol (C53): {}",
            result.summary
        );
    }
}
