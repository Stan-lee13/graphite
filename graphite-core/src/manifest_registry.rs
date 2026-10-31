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
//!   it too — a submission can never name its own tier. A revoked reviewer's
//!   signature and attestations stop counting, and the tiers in force are
//!   recomputed from the reviewers registered NOW (`revoke_reviewer`).
//! - **G5 independence:** `community_verified_count` counts only DISTINCT
//!   registered reviewers (reputation ≥ `MIN_REVIEWER_REPUTATION`) whose
//!   attestation signature verifies over the submission's signing message —
//!   one attestation per (program, version) per reviewer. Duplicate, invalid,
//!   and unregistered attestations are dropped.
//! - **What is signed:** [`signing_message`] — a domain tag, the program id
//!   and the canonical content hash ([`canonical_manifest_json`]), never the
//!   bare hash string, so no signature made for anything else verifies here.
//! - **Anonymous signing is worthless (P7):** a valid ed25519 signature by an
//!   UNREGISTERED key earns no tier. A signature by a low-reputation
//!   registered key is rejected outright.
//! - **Append-only (P4):** accepted submissions are recorded in an append-only
//!   log with version lineage. A submission must name the version in force as
//!   its `previous_version_ref` (or be the program's first), and no label or
//!   content hash the registry has accepted, or refused at the replay gate, is
//!   ever taken again — so an older signed version cannot be rolled in over a
//!   newer one.
//! - **P10 gate:** EVERY submission is replayed — the engine runs the replay
//!   ITSELF, against a core carrying the CANDIDATE manifest, over the
//!   registry's OWN regression corpus for the program plus whatever fixtures
//!   the submitter supplies. The registry's corpus holds the fixtures of every
//!   version it has accepted (including the refusals that pinned them) and is
//!   persisted with the registry's state, so a submission can add fixtures
//!   but never remove one: leaving a refusal fixture out of the corpus handed
//!   in does not take it out of the replay. A caller can never hand it a
//!   fabricated "passing" run.
//!
//!   **What the first-submission gate does and does not prove.** A brand-new
//!   program has no prior recorded behaviour, so there is nothing for its first
//!   submission to regress AGAINST. A fixture recorded under the candidate
//!   manifest and immediately replayed under the same manifest agrees with
//!   itself by construction. The requirement is therefore not a validation of
//!   the new manifest — claiming otherwise would be overclaiming. What it buys
//!   is that the regression baseline EXISTS: the program cannot be enshrined
//!   with an empty history, so its first upgrade has something to be held to.
//!   The submitter still chooses which transactions to pin, which is the same
//!   assumption the upgrade path makes for the fixtures it ADDS.
//!
//!   **So a first manifest's tier is capped** (Round 40, R39-CORE-IDENTITY-7,
//!   owner decision option 4). A version whose replay validated nothing
//!   independent of it — the program's first, the head handed in again, or
//!   an upgrade replayed against no fixture an earlier version pinned (every
//!   one retired) — is recorded with `first_manifest_unvalidated`, and its
//!   registry evidence earns `HeuristicInferred` at most
//!   (`semantic_graph_store::compute_trust_tier_for`): in the record, in the
//!   manifest in force and in the graph record, the two sources of the
//!   verdict's tier. Signatures and attestations are still recorded. The cap
//!   lifts when an upgrade passes the gate against fixtures an earlier
//!   version pinned, or when measured battle-tested volume reaches the
//!   `BattleTested` threshold (a census-backed record); an operator's
//!   assertion of signatures or attestations does not lift it.
//! - **P11:** trust is keyed by the exact `programId` string — no fuzzy match.
//!
//! Registry submissions reach at most Tier 4 (`CommunityVerified`): Tier 5
//! (`BattleTested`) requires 1,000+ battle-tested transactions in the
//! program's graph evidence, which is operator-asserted (seeded by an
//! operator), never attested through the registry.

use crate::confidence_engine::TrustTier;
use crate::manifest::ProtocolManifest;
use crate::regression_engine::{
    decide_promotion, replay_corpus_for_program, PromotionDecision, RegressionCorpus,
};
use crate::semantic_graph_store::{
    compute_trust_tier_for, Behavior, BehaviorEvidence, SemanticGraphStore,
};
use crate::verification::GraphiteCore;
use std::collections::{BTreeSet, HashMap, HashSet};
use thiserror::Error;

/// Minimum demonstrated reputation for a reviewer's signature/attestation to
/// count (G5). Operational parameter, not a security boundary on its own.
pub const MIN_REVIEWER_REPUTATION: u64 = 100;

/// The domain tag every registry signature begins with (Round 29, audit
/// 2026-10-20, MR-3). See [`signing_message`].
pub const SIGNING_DOMAIN: &[u8] = b"graphite-manifest-registry-v1\0";

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
    #[error("version {0} of this program was already accepted; a registry never re-accepts a version, so an old submission cannot be replayed over a newer one")]
    VersionAlreadyAccepted(String),
    /// The submission does not name the version in force as its predecessor
    /// (Round 29, audit 2026-10-20, MR-2).
    #[error("lineage: the version in force is {head:?}, and this submission names {named:?} as its previous_version_ref — a submission must build on the version in force, so an older signed version can never be rolled in over a newer one")]
    StaleLineage {
        head: Option<String>,
        named: Option<String>,
    },
    /// The registry's replay gate refused this label or content before (MR-2).
    #[error("version {0} of this program (or its exact content) was refused by the regression gate before; a refused version is never taken again — correct it under a new label")]
    VersionPreviouslyRefused(String),
    /// The key is not a usable ed25519 public key (MR-6).
    #[error("reviewer pubkey {0:?} is not a valid ed25519 public key (base58, 32 bytes, a point on the curve)")]
    MalformedReviewerPubkey(String),
    /// The key was revoked; revocation is permanent (MR-6).
    #[error(
        "reviewer {0} was revoked; a revoked key is never registered again — register a new key"
    )]
    ReviewerRevoked(String),
    #[error("reviewer {0} is not registered")]
    UnknownReviewer(String),
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

/// An independent reviewer attestation over a submission's signing message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReviewerAttestation {
    pub reviewer_pubkey: String,
    /// hex-encoded ed25519 signature over [`signing_message`].
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

/// The canonical JSON form of a manifest — what the content hash covers
/// (Round 29, audit 2026-10-20, MR-4).
///
/// The form: the JSON value serde produces for the PARSED
/// [`ProtocolManifest`], written with
///
/// - the keys of every object sorted by their UTF-8 bytes, at every level;
/// - no whitespace outside strings;
/// - strings and numbers in serde_json's encoding (`\"`, `\\`, `\n`, `\uXXXX`
///   for control characters; integers in plain decimal).
///
/// Because it is the parsed manifest, a field absent from the submitted
/// document hashes as its default, and the documentation-only fields the
/// parser does not keep (`protocol.note`, `protocol.idl_source`,
/// `protocol.superseded`, the top-level `verification` block) are not
/// covered: they never reach the registry. Field ORDER in the document, and
/// the order in which the struct happens to declare its fields, no longer
/// change the hash — it was `serde_json::to_string` of the struct, which is
/// declaration-ordered and changes whenever a field is added or moved.
pub fn canonical_manifest_json(manifest: &ProtocolManifest) -> String {
    fn write(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String(k.clone()).to_string());
                    out.push(':');
                    write(&map[k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let value = serde_json::to_value(manifest).expect("a manifest is plain data");
    let mut out = String::new();
    write(&value, &mut out);
    out
}

/// The exact bytes a registry signature or attestation signs (Round 29, audit
/// 2026-10-20, MR-3):
///
/// ```text
/// b"graphite-manifest-registry-v1\0" || program_id || b"\0" || content_hash_hex
/// ```
///
/// Signatures used to cover the bare 64-character hex string. Reviewer keys
/// are ordinary ed25519 keys — Solana wallet keys — so any signature that key
/// ever made over that string (a wallet `signMessage` prompt showing a hash,
/// say) verified as an attestation. The domain tag makes a registry signature
/// one that could only have been made for the registry, and the program id
/// binds it to the program as well as to the content. Submission, attestation
/// and verification all build the message here; a signing tool must too.
pub fn signing_message(program_id: &str, content_hash_hex: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNING_DOMAIN.len() + program_id.len() + 1 + 64);
    m.extend_from_slice(SIGNING_DOMAIN);
    m.extend_from_slice(program_id.as_bytes());
    m.push(0);
    m.extend_from_slice(content_hash_hex.as_bytes());
    m
}

impl ManifestSubmission {
    /// The deterministic content hash: hex SHA-256 of the canonical manifest
    /// JSON ([`canonical_manifest_json`]).
    pub fn content_hash(&self) -> String {
        Self::content_hash_of(&self.manifest)
    }

    /// What the submitter signs and each reviewer attests: [`signing_message`]
    /// over this manifest's program and content hash.
    pub fn signing_message(&self) -> Vec<u8> {
        signing_message(&self.manifest.protocol.program_id, &self.content_hash())
    }

    fn content_hash_of(manifest: &ProtocolManifest) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(canonical_manifest_json(manifest).as_bytes()))
    }
}

/// One accepted submission in the append-only acceptance log (P4).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RegistryRecord {
    pub program_id: String,
    pub version_label: String,
    pub previous_version_ref: Option<String>,
    pub content_hash: String,
    /// The tier computed when the version was accepted. The tier IN FORCE is
    /// recomputed from the reviewers registered now (see
    /// [`ManifestRegistryEngine::manifests_in_force`]).
    pub trust_tier: TrustTier,
    /// "signed" (registered-reporter signature) or "community" (attestations).
    pub source: String,
    /// The full accepted manifest, retained so community-accepted manifests
    /// can be merged into the runtime verification registry (C53). `None`
    /// for records persisted before this field existed (serde default).
    #[serde(default)]
    pub manifest: Option<ProtocolManifest>,
    /// The reviewer whose signature counted, if any (Round 29, MR-6). Absent
    /// on records written before revocation existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// The independent reviewers whose attestations counted (MR-6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attesters: Vec<String>,
    /// Round 36 (F-008): the signer's signature that counted, kept so a third
    /// party holding only this record can check it ([`RegistryRecord::verify_offline`]).
    /// Absent on records written before Round 36.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Round 36 (F-008): every attestation that counted, signature included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestation_signatures: Vec<ReviewerAttestation>,
    /// Round 36 (F-008): the domain tag the signatures were made under
    /// ([`SIGNING_DOMAIN`] without its NUL), so a verifier rebuilds exactly
    /// the message they cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_domain: Option<String>,
    /// Round 40 (R39-CORE-IDENTITY-7): this version's replay validated
    /// nothing independent of it — it is the program's first, or the head
    /// handed in again, or an upgrade replayed against no fixture an earlier
    /// version pinned. Its tier is capped at `HeuristicInferred`
    /// ([`compute_trust_tier_for`]). Absent on records written before Round
    /// 40, which keep the tier they were accepted at.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub first_manifest_unvalidated: bool,
}

impl RegistryRecord {
    /// Check this record from its own contents, without the registry
    /// (Round 36, F-008): the retained manifest hashes to `content_hash`, and
    /// every retained signature verifies over [`signing_message`] for this
    /// program and hash, under the domain the record names. It says the named
    /// keys signed this content; whether those keys were reviewers with
    /// standing is the registry's state at acceptance, which the auditor
    /// checks against the reviewer list it was given. A record written
    /// before Round 36 retains no signatures and is reported as such, never
    /// as verified.
    pub fn verify_offline(&self) -> Result<(), String> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or("the record retains no manifest, so its content cannot be rehashed")?;
        let rehashed = ManifestSubmission::content_hash_of(manifest);
        if rehashed != self.content_hash {
            return Err(format!(
                "the retained manifest hashes to {rehashed}, not the recorded {}",
                self.content_hash
            ));
        }
        if manifest.protocol.program_id != self.program_id {
            return Err("the retained manifest is for another program".to_string());
        }
        let domain =
            String::from_utf8_lossy(SIGNING_DOMAIN.strip_suffix(b"\0").unwrap_or(SIGNING_DOMAIN))
                .into_owned();
        match &self.signing_domain {
            Some(d) if *d == domain => {}
            Some(d) => return Err(format!("the record was signed under domain {d:?}, not {domain:?}")),
            None => {
                return Err(
                    "the record predates retained signatures (Round 36): nothing in it can be checked offline"
                        .to_string(),
                )
            }
        }
        if self.signer.is_none() && self.attesters.is_empty() {
            return Err("the record names no signer and no attester".to_string());
        }
        // Round 38 (Round 37, V-5): the signatures were checked and the
        // record's own claims about them were not. A record whose source,
        // tier or attester list says more than its signatures support is
        // not the record the registry wrote.
        let mut distinct: Vec<&str> = self.attesters.iter().map(String::as_str).collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() != self.attesters.len() {
            return Err("the record names the same attester twice".to_string());
        }
        match (self.source.as_str(), &self.signer) {
            ("signed", Some(_)) | ("community", None) => {}
            (source, signer) => {
                return Err(format!(
                    "the record's source is {source:?} and it {} a signer",
                    if signer.is_some() {
                        "names"
                    } else {
                        "names no"
                    }
                ))
            }
        }
        let needed = crate::semantic_graph_store::thresholds::COMMUNITY_VERIFIED as usize;
        match self.trust_tier {
            TrustTier::BattleTested => {
                return Err(
                    "the record claims BattleTested, which no registry submission reaches"
                        .to_string(),
                )
            }
            TrustTier::CommunityVerified if distinct.len() < needed => {
                return Err(format!(
                    "the record claims CommunityVerified with {} attester(s); it takes {needed}",
                    distinct.len()
                ))
            }
            // Round 40 (R39-CORE-IDENTITY-7).
            tier if self.first_manifest_unvalidated && tier > TrustTier::HeuristicInferred => {
                return Err(format!(
                    "the record claims {tier:?} for a manifest no independent replay has validated; it is capped at HeuristicInferred"
                ))
            }
            _ => {}
        }
        if let Some(signer) = &self.signer {
            let sig = self
                .signature_hex
                .as_deref()
                .ok_or("the record names a signer and retains no signature")?;
            if !ManifestRegistryEngine::verify_signature(
                signer,
                sig,
                &self.program_id,
                &self.content_hash,
            ) {
                return Err(format!(
                    "{signer}'s signature does not verify over this record"
                ));
            }
        }
        let retained: Vec<&str> = self
            .attestation_signatures
            .iter()
            .map(|a| a.reviewer_pubkey.as_str())
            .collect();
        if retained
            != self
                .attesters
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            return Err(
                "the retained attestations are not the attesters the record names".to_string(),
            );
        }
        for a in &self.attestation_signatures {
            if !ManifestRegistryEngine::verify_signature(
                &a.reviewer_pubkey,
                &a.signature_hex,
                &self.program_id,
                &self.content_hash,
            ) {
                return Err(format!(
                    "{}'s attestation does not verify over this record",
                    a.reviewer_pubkey
                ));
            }
        }
        Ok(())
    }
}

/// A version the replay gate refused (MR-2): its label and content are never
/// taken again for this program.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefusedSubmission {
    pub program_id: String,
    pub version_label: String,
    pub content_hash: String,
    pub reason: String,
}

/// The community Manifest Registry engine.
///
/// Persisted whole (`to_json` / `from_json`). Every field added in Round 29
/// is `serde(default)`, so a state file written before it loads with them
/// empty.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ManifestRegistryEngine {
    /// Registered reviewers: pubkey → identity + demonstrated reputation (G5).
    reviewers: HashMap<String, RegistryReviewer>,
    /// Append-only acceptance log with version lineage (P4).
    records: Vec<RegistryRecord>,
    /// Reviewers whose keys were revoked (MR-6). Never registered again.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    revoked_reviewers: BTreeSet<String>,
    /// Versions the replay gate refused (MR-2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refused: Vec<RefusedSubmission>,
    /// The registry's own regression corpus (MR-1): every fixture of every
    /// version it has accepted, for every program. Replayed on every
    /// submission in addition to whatever the submitter supplies; a
    /// submission can add to it and never remove from it.
    #[serde(default)]
    corpus: RegressionCorpus,
}

impl ManifestRegistryEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a reviewer identity with a demonstrated reputation score.
    /// Operator API (Phase 2: operator-verified stake/GitHub claim).
    ///
    /// Round 29 (audit 2026-10-20, MR-6): the key must be a usable ed25519
    /// public key — base58, 32 bytes, a valid curve point. Any non-empty
    /// string was accepted, so a typo registered a reviewer whose signatures
    /// could never verify, and nothing said so. A revoked key is refused.
    pub fn register_reviewer(
        &mut self,
        pubkey: &str,
        reputation_score: u64,
    ) -> Result<(), RegistryError> {
        if pubkey.trim().is_empty() {
            return Err(RegistryError::InvalidReviewerPubkey);
        }
        if parse_verifying_key(pubkey).is_none() {
            return Err(RegistryError::MalformedReviewerPubkey(pubkey.to_string()));
        }
        if self.revoked_reviewers.contains(pubkey) {
            return Err(RegistryError::ReviewerRevoked(pubkey.to_string()));
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

    /// Revoke a reviewer (Round 29, audit 2026-10-20, MR-6). Operator API.
    ///
    /// The key leaves the registered set for good, and its signature and
    /// attestations stop counting wherever they counted: the tier of every
    /// manifest in force is recomputed from the reviewers registered now
    /// ([`Self::manifests_in_force`]), and every program whose version in
    /// force the key had signed or attested gets a new Semantic Graph record
    /// carrying the recomputed registry evidence (append-only, P4; the
    /// program's other evidence is kept, G-3). Returns how many programs were
    /// re-recorded.
    ///
    /// A version accepted before records named their reviewers (no `signer`
    /// or `attesters` on the record) cannot be recomputed and keeps the tier
    /// it was accepted at.
    pub fn revoke_reviewer(
        &mut self,
        store: &mut SemanticGraphStore,
        pubkey: &str,
    ) -> Result<usize, RegistryError> {
        if self.reviewers.remove(pubkey).is_none() {
            return Err(RegistryError::UnknownReviewer(pubkey.to_string()));
        }
        self.revoked_reviewers.insert(pubkey.to_string());
        let mut touched = 0;
        let heads: Vec<RegistryRecord> = self.heads().into_iter().cloned().collect();
        for head in heads {
            let involved = head.signer.as_deref() == Some(pubkey)
                || head.attesters.iter().any(|a| a == pubkey);
            if !involved {
                continue;
            }
            let evidence = self.evidence_in_force(&head);
            store
                .append_registry_evidence(Behavior {
                    program_id: head.program_id.clone(),
                    version: head.version_label.clone(),
                    expected_state_changes: head
                        .manifest
                        .iter()
                        .flat_map(|m| m.instructions.iter())
                        .flat_map(|ix| ix.expected_state_changes.iter().cloned())
                        .collect(),
                    allowed_cpis: head
                        .manifest
                        .iter()
                        .flat_map(|m| m.instructions.iter())
                        .flat_map(|ix| ix.allowed_cpis.iter().cloned())
                        .collect(),
                    trust_tier: TrustTier::Unknown, // recomputed by append (P7)
                    evidence,
                    quarantined: false,
                    quarantine_reason: None,
                    // Revocation validates nothing (Round 40).
                    first_manifest_unvalidated: head.first_manifest_unvalidated,
                })
                .map_err(|_| RegistryError::EmptyProgramId)?;
            touched += 1;
        }
        Ok(touched)
    }

    /// Reviewer keys that have been revoked.
    pub fn revoked_reviewers(&self) -> &BTreeSet<String> {
        &self.revoked_reviewers
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

    /// Versions the replay gate refused (MR-2).
    pub fn refused(&self) -> &[RefusedSubmission] {
        &self.refused
    }

    /// The registry's own regression corpus (MR-1).
    pub fn regression_corpus(&self) -> &RegressionCorpus {
        &self.corpus
    }

    /// Operator action: deprecate one fixture of the registry's corpus, by
    /// its identity (`content_hash`). The escape hatch for a correction that
    /// legitimately changes a pinned outcome — a submission cannot remove a
    /// fixture, but an operator can retire one, deliberately and by name. A
    /// deprecated fixture stays in the corpus (P4) and leaves the pass-rate
    /// denominator.
    pub fn deprecate_regression_fixture(&mut self, content_hash: &str) -> bool {
        self.corpus.deprecate(content_hash)
    }

    /// Last accepted record for a program (version lineage head).
    pub fn last_accepted(&self, program_id: &str) -> Option<&RegistryRecord> {
        self.records
            .iter()
            .rev()
            .find(|r| r.program_id == program_id)
    }

    /// The head record of every program, in order of each program's first
    /// acceptance (P2).
    fn heads(&self) -> Vec<&RegistryRecord> {
        let mut order: Vec<&str> = Vec::new();
        let mut latest: HashMap<&str, &RegistryRecord> = HashMap::new();
        for record in &self.records {
            let key = record.program_id.as_str();
            if latest.insert(key, record).is_none() {
                order.push(key);
            }
        }
        order.into_iter().filter_map(|k| latest.remove(k)).collect()
    }

    /// The registry evidence a record carries NOW: its signer if still a
    /// registered reviewer of sufficient reputation, and its attesters that
    /// still are (MR-6). A record that names no reviewer (written before
    /// reviewers were recorded) has no evidence to reconstruct; callers use
    /// its stored tier instead (`tier_in_force`).
    fn evidence_in_force(&self, record: &RegistryRecord) -> BehaviorEvidence {
        let counts = |k: &str| {
            self.reviewer_reputation(k)
                .is_some_and(|r| r >= MIN_REVIEWER_REPUTATION)
        };
        BehaviorEvidence {
            has_signed_manifest: record.signer.as_deref().is_some_and(counts),
            community_verified_count: record
                .attesters
                .iter()
                .filter(|a| counts(a))
                .count()
                .try_into()
                .unwrap_or(u32::MAX),
            ..Default::default()
        }
    }

    /// The tier a record supports with the reviewers registered now, capped
    /// while its manifest is unvalidated (Round 40, R39-CORE-IDENTITY-7).
    fn tier_in_force(&self, record: &RegistryRecord) -> TrustTier {
        if record.signer.is_none() && record.attesters.is_empty() {
            return record.trust_tier;
        }
        compute_trust_tier_for(
            &self.evidence_in_force(record),
            record.first_manifest_unvalidated,
        )
    }

    /// The CURRENT accepted manifest for each program — the last one accepted,
    /// emitted in order of each program's first acceptance so the sequence is
    /// deterministic (P2).
    ///
    /// This yielded every record in acceptance order until 2026-09-05, which
    /// made manifest upgrades silently inert: `merge_community` skips a program
    /// already present in the registry, so it took the FIRST accepted version
    /// and dropped every later one. A protocol shipping a corrected manifest
    /// was told ACCEPTED, the acceptance log recorded the new version and its
    /// lineage, the dashboard showed it — and `verify` went on resolving
    /// instructions against the original. A manifest fix that TIGHTENED a rule
    /// (a corrected account list, an added risk rule) never took effect.
    ///
    /// The append-only log is untouched (P4): every version is still recorded.
    /// This is only about which one is in force.
    ///
    /// Records persisted before the `manifest` field existed (serde default
    /// `None`) are skipped. The verification core merges these into its
    /// runtime registry (C53) so community-accepted protocols actually resolve
    /// at verification time, not just in the dashboard.
    ///
    /// Each manifest carries the tier the registry COMPUTES for it in place
    /// of the one its document declares (A3-06, 2026-09-29 audit) — and
    /// computes from the reviewers registered NOW, so a revoked reviewer's
    /// signature or attestation no longer holds the tier up (Round 29, MR-6).
    /// The runtime reads a manifest's `trust_tier` on the verdict path; a
    /// submission earning HeuristicInferred from one attestation that wrote
    /// "OfficialManifest" into its own document was verified at
    /// OfficialManifest. P7: a tier is computed from evidence, never
    /// asserted. This is what a verification core merges.
    pub fn manifests_in_force(&self) -> Vec<ProtocolManifest> {
        self.records_in_force()
            .into_iter()
            .map(|(record, manifest)| {
                let mut m = manifest.clone();
                m.trust_tier = self.tier_in_force(record).as_str().to_string();
                m
            })
            .collect()
    }

    /// The latest record carrying a manifest, per program, in order of each
    /// program's first such record.
    fn records_in_force(&self) -> Vec<(&RegistryRecord, &ProtocolManifest)> {
        let mut order: Vec<&str> = Vec::new();
        let mut latest: HashMap<&str, (&RegistryRecord, &ProtocolManifest)> = HashMap::new();
        for record in &self.records {
            let Some(manifest) = record.manifest.as_ref() else {
                continue;
            };
            let key = record.program_id.as_str();
            if latest.insert(key, (record, manifest)).is_none() {
                order.push(key);
            }
        }
        order.into_iter().filter_map(|k| latest.remove(k)).collect()
    }

    /// The manifests in force, as accepted (their documents' own tiers). See
    /// [`Self::manifests_in_force`] for what a verification core merges.
    pub fn accepted_manifests(&self) -> impl Iterator<Item = &ProtocolManifest> {
        self.records_in_force().into_iter().map(|(_, m)| m)
    }

    /// Submit a community manifest.
    ///
    /// `regression` is required for every submission (P10): the engine runs
    /// the replay itself, over its own corpus for the program plus the
    /// supplied one, so a fabricated "passing" run is impossible and an
    /// omitted fixture is still replayed (MR-1).
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
        // Schema validation — the runtime loader's own (MR-5): a manifest the
        // loader would refuse must not be enshrined at an earned tier.
        Self::validate_manifest(&submission.manifest)?;
        let content_hash = submission.content_hash();
        let version_label = submission.manifest.version.label.clone();

        // MR-2: a label or content the replay gate refused is never taken
        // again — after a fixture is deprecated, or the core changes, the
        // same refused manifest must not slip through on a second try.
        if self.refused.iter().any(|r| {
            r.program_id == program_id
                && (r.version_label == version_label || r.content_hash == content_hash)
        }) {
            return Err(RegistryError::VersionPreviouslyRefused(version_label));
        }

        // A3-07 (2026-09-29 audit): a version is accepted once. Signatures
        // and attestations cover the manifest alone, so anyone holding an
        // old accepted submission could hand it in again after a correction;
        // it verified, it was not a promotion (so no replay gate ran), and as
        // the newest record it became the manifest in force — the correction
        // rolled back with no new signature. A label or a content hash the log
        // already holds for this program is refused.
        //
        // One exception (review of that fix, F11): the manifest IN FORCE (the
        // program's newest record), handed in again unchanged with evidence
        // that earns it a HIGHER tier — more attesters. That cannot roll
        // anything back (it is the head), and without it the only way to
        // raise an accepted version's tier was to relabel identical content.
        let head = self.last_accepted(&program_id).cloned();
        let head_tier = head
            .as_ref()
            .filter(|h| h.content_hash == content_hash && h.version_label == version_label)
            .map(|h| self.tier_in_force(h));
        if head_tier.is_none()
            && self.records.iter().any(|r| {
                r.program_id == program_id
                    && (r.version_label == version_label || r.content_hash == content_hash)
            })
        {
            return Err(RegistryError::VersionAlreadyAccepted(version_label));
        }

        // Evidence from the submission — P7: tier derived, never asserted.
        let (evidence, signer, counted_attestations) =
            self.evidence_from_submission(&submission, &content_hash)?;
        let attesters: Vec<String> = counted_attestations
            .iter()
            .map(|a| a.reviewer_pubkey.clone())
            .collect();
        if !evidence.has_signed_manifest && evidence.community_verified_count == 0 {
            return Err(RegistryError::NoEvidence);
        }
        // Round 40 (R39-CORE-IDENTITY-7, owner decision option 4): whether
        // this version's replay can validate anything. A first submission's
        // fixtures are recorded under the candidate and agree with it by
        // construction; the head handed in again is replayed against its own
        // fixtures; an upgrade is held to the fixtures earlier versions
        // pinned, which it did not write — unless there are none left in
        // force. Unvalidated, the registry evidence earns HeuristicInferred
        // at most, in the record, in the manifest in force and in the graph.
        let independent_fixtures = self
            .corpus
            .fixtures_for(&program_id)
            .into_iter()
            .filter(|f| !f.deprecated)
            .count();
        // Round 41 (external review, D-30): the earlier versions' fixtures are
        // independent of THIS upgrade only when none of its keys wrote them.
        // While the program is still unvalidated, every fixture in force was
        // written by the keys of its earlier submissions; an upgrade signed or
        // attested by any of them replays its own reviewers' fixtures, which a
        // self-consistent manifest passes by construction — the same thing D-9
        // caps a first manifest for. It stays capped; an upgrade from disjoint
        // keys, or measured volume, still lifts the cap.
        let written_by_these_keys = || {
            let ours: std::collections::HashSet<&str> = signer
                .iter()
                .map(String::as_str)
                .chain(attesters.iter().map(String::as_str))
                .collect();
            self.records
                .iter()
                .filter(|r| r.program_id == program_id)
                .flat_map(|r| r.signer.iter().chain(r.attesters.iter()))
                .any(|k| ours.contains(k.as_str()))
        };
        let unvalidated = match &head {
            None => true,
            Some(h) if head_tier.is_some() => h.first_manifest_unvalidated,
            Some(h) => {
                independent_fixtures == 0
                    || (h.first_manifest_unvalidated && written_by_these_keys())
            }
        };
        let tier = compute_trust_tier_for(&evidence, unvalidated);
        if head_tier.is_some_and(|head| tier <= head) {
            // The head again, with nothing new: a replay.
            return Err(RegistryError::VersionAlreadyAccepted(version_label));
        }

        // MR-2 (Round 29, audit 2026-10-20): the lineage is enforced. A
        // version builds on the version in force — its `previous_version_ref`
        // names the head's label — or it is the program's first. The ref used
        // to be recorded and never compared, so a version signed long ago
        // against v1 (and never submitted) could be handed in after v3 and,
        // passing the replay, become the manifest in force: a rollback with
        // a valid signature. The head handed in again (above) keeps its own
        // lineage. Such a refusal is permanent by construction — the head
        // never goes back to an older label — so it is not recorded.
        if let Some(head) = &head {
            if head_tier.is_none()
                && submission.manifest.version.previous_version_ref.as_deref()
                    != Some(head.version_label.as_str())
            {
                return Err(RegistryError::StaleLineage {
                    head: Some(head.version_label.clone()),
                    named: submission.manifest.version.previous_version_ref.clone(),
                });
            }
        }

        // P10 gate, on EVERY submission (MR-1). A first submission moves the
        // program from no trust to some trust (2026-09-05: exempting it left
        // the gate protecting only upgrades); an upgrade replaces the manifest
        // in force (W12: a loosening v2 at the same tier went in unreplayed);
        // a head resubmitted for a higher tier promotes it. Whatever the case,
        // the replay covers the registry's OWN fixtures for the program —
        // every accepted version's, persisted with the registry — plus the
        // submitter's, so a refusal fixture left out of the submitted corpus
        // is replayed anyway (MR-1: the gate used to replay only what the
        // submitter handed it).
        let (submitted, core) = regression.ok_or_else(|| {
            RegistryError::RegressionGateBlocked(
                "no regression corpus supplied — every submission is replayed (P10)".to_string(),
            )
        })?;
        submitted.verify_integrity().map_err(|e| {
            RegistryError::RegressionGateBlocked(format!("the supplied corpus is not intact: {e}"))
        })?;
        let mut replay = RegressionCorpus::new();
        for f in self.corpus.fixtures_for(&program_id) {
            replay.add_fixture(f.clone());
        }
        for f in submitted.fixtures_for(&program_id) {
            // Same identity as a registry fixture: the registry's recorded
            // outcome wins (`add_fixture` keeps the first), so a submitter
            // cannot flip a pinned outcome by resubmitting its input.
            replay.add_fixture(f.clone());
        }
        // Replay against the manifest the submission WOULD install, not the
        // one it replaces, at the tier the registry computed (W12) — the tier
        // `manifests_in_force` hands the runtime, not the document's own.
        let mut candidate = submission.manifest.clone();
        candidate.trust_tier = tier.as_str().to_string();
        let candidate_core = core
            .with_candidate_manifest(&candidate)
            .map_err(|e| RegistryError::RegressionGateBlocked(e.to_string()))?;
        let run = replay_corpus_for_program(&candidate_core, &replay, &program_id);
        if let PromotionDecision::Block { reason } =
            Self::gate_decision(&run, &self.corpus, &program_id)
        {
            self.refused.push(RefusedSubmission {
                program_id: program_id.clone(),
                version_label: version_label.clone(),
                content_hash: content_hash.clone(),
                reason: reason.clone(),
            });
            return Err(RegistryError::RegressionGateBlocked(reason));
        }

        // P4: append to the Semantic Graph (append recomputes the tier) and to
        // the acceptance log with version lineage. G-3: the program's other
        // graph evidence (operator-asserted volume, simulation matches) is
        // carried forward, not reset by a manifest version.
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
            .append_registry_evidence(Behavior {
                program_id: program_id.clone(),
                version: version_label.clone(),
                expected_state_changes,
                allowed_cpis,
                trust_tier: TrustTier::Unknown, // ignored — recomputed by append (P7)
                evidence: evidence.clone(),
                quarantined: false,
                quarantine_reason: None,
                first_manifest_unvalidated: unvalidated,
            })
            // append's only error is an empty program_id, which was rejected
            // above (EmptyProgramId) — unreachable here.
            .expect("append cannot fail after program_id validation");

        // MR-1: the accepted version's fixtures join the registry's corpus.
        for f in submitted.fixtures_for(&program_id) {
            self.corpus.add_fixture(f.clone());
        }

        let previous_version_ref = head
            .as_ref()
            .filter(|_| head_tier.is_none())
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
            signature_hex: signer.as_ref().and(submission.signature_hex.clone()),
            signer,
            attesters,
            attestation_signatures: counted_attestations,
            signing_domain: Some(
                String::from_utf8_lossy(
                    SIGNING_DOMAIN.strip_suffix(b"\0").unwrap_or(SIGNING_DOMAIN),
                )
                .into_owned(),
            ),
            first_manifest_unvalidated: unvalidated,
        });

        Ok(RegistryDecision::Accepted {
            trust_tier: tier,
            version_label,
        })
    }

    /// The P10 decision over a replay (Round 39, R39-CORE-IDENTITY-1).
    ///
    /// `decide_promotion` alone took 99.5% of the whole replay, and the
    /// whole replay included the submitter's fixtures: recorded under the
    /// candidate, they pass by construction, and one input can be pinned under
    /// any number of provenance strings. 199 of them let one fixture fail —
    /// and the one that failed could be a refusal the registry pinned when it
    /// accepted an earlier version, approved by the candidate. "A submission
    /// can add fixtures but never remove one" (MR-1) did not hold. Now:
    ///
    /// - a fixture pinned as REFUSED that the candidate approves blocks,
    ///   whatever the pass rate — a loosening of pinned behaviour is the case
    ///   the gate exists for, and a correction that legitimately approves it
    ///   goes through the operator's named escape hatch
    ///   ([`Self::deprecate_regression_fixture`]);
    /// - the registry's own non-deprecated fixtures are held to the pass rate
    ///   on their own, so the submitter's fixtures cannot dilute them;
    /// - the whole replay is held to it as before.
    fn gate_decision(
        run: &crate::regression_engine::RegressionRun,
        registry_corpus: &RegressionCorpus,
        program_id: &str,
    ) -> PromotionDecision {
        if let Some(f) = run.failures.iter().find(|f| !f.expected && f.got) {
            return PromotionDecision::Block {
                reason: format!(
                    "fixture {} was pinned as refused and the candidate approves it: a submission may not loosen pinned behaviour, whatever the pass rate (an operator retires a fixture by name to allow a correction)",
                    f.content_hash
                ),
            };
        }
        let pinned: HashSet<&str> = registry_corpus
            .fixtures_for(program_id)
            .into_iter()
            .filter(|f| !f.deprecated)
            .map(|f| f.content_hash.as_str())
            .collect();
        if !pinned.is_empty() {
            let failed = run
                .failures
                .iter()
                .filter(|f| pinned.contains(f.content_hash.as_str()))
                .count();
            let rate = pinned.len().saturating_sub(failed) as f64 / pinned.len() as f64;
            if rate < crate::regression_engine::PROMOTION_PASS_RATE {
                return PromotionDecision::Block {
                    reason: format!(
                        "the registry's own fixtures for this program pass at {rate:.4}, below the required {:.3} ({failed} failed / {} pinned); the submitter's fixtures do not count toward it",
                        crate::regression_engine::PROMOTION_PASS_RATE,
                        pinned.len()
                    ),
                };
            }
        }
        decide_promotion(run)
    }

    /// Validate the manifest surface: the runtime loader's full validation
    /// (`manifest::validate_manifest` — Round 29, audit 2026-10-20, MR-5: this
    /// was a partial copy of its rules, weaker than the validator a merged
    /// manifest then had to pass), plus the registry's own resource caps and
    /// its stricter rule on empty discriminators.
    fn validate_manifest(manifest: &ProtocolManifest) -> Result<(), RegistryError> {
        // The resource caps run FIRST: they bound the work the full
        // validation below does (its prefix-ambiguity check is quadratic in
        // the instruction count).
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
        for ix in &manifest.instructions {
            if ix.account_layouts.len() > 4 {
                return Err(RegistryError::InvalidManifest(format!(
                    "instruction '{}' declares {} alternate account layouts (cap 4) — resource-exhaustion guard",
                    ix.name,
                    ix.account_layouts.len()
                )));
            }
        }
        for ix in &manifest.instructions {
            if ix.name.chars().count() > MAX_FIELD_CHARS {
                return Err(RegistryError::InvalidManifest(format!(
                    "instruction name exceeds {MAX_FIELD_CHARS} chars"
                )));
            }
            if ix
                .all_layouts()
                .any(|l| l.len() > MAX_ACCOUNTS_PER_INSTRUCTION)
            {
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
        crate::manifest::validate_manifest(manifest)
            .map_err(|e| RegistryError::InvalidManifest(e.to_string()))
    }

    /// Derive BehaviorEvidence from a submission (G5 + P7), with the signer
    /// and the independent attesters that counted (MR-6).
    fn evidence_from_submission(
        &self,
        submission: &ManifestSubmission,
        content_hash: &str,
    ) -> Result<(BehaviorEvidence, Option<String>, Vec<ReviewerAttestation>), RegistryError> {
        let mut evidence = BehaviorEvidence::default();
        let program_id = submission.manifest.protocol.program_id.as_str();
        let mut counted_signer: Option<String> = None;
        let mut counted_attesters: Vec<ReviewerAttestation> = Vec::new();

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
            if !Self::verify_signature(signer, sig, program_id, content_hash) {
                return Err(RegistryError::InvalidSignature(
                    "signer signature does not verify over the registry signing message"
                        .to_string(),
                ));
            }
            if self.revoked_reviewers.contains(signer) {
                return Err(RegistryError::ReviewerRevoked(signer.clone()));
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
            counted_signer = Some(signer.clone());
        }

        // 2. Independent attestations (G5): distinct registered reviewers with
        // valid signatures only; one attestation per reviewer per content.
        let mut counted: HashSet<String> = HashSet::new();
        for attestation in &submission.attestations {
            let Some(reputation) = self.reviewer_reputation(&attestation.reviewer_pubkey) else {
                continue; // unregistered (or revoked) reviewer contributes nothing
            };
            if reputation < MIN_REVIEWER_REPUTATION {
                continue;
            }
            if !Self::verify_signature(
                &attestation.reviewer_pubkey,
                &attestation.signature_hex,
                program_id,
                content_hash,
            ) {
                continue; // invalid attestation is dropped, not an error
            }
            if !counted.insert(attestation.reviewer_pubkey.clone()) {
                continue; // one attestation per reviewer per content
            }
            // W11 (external review): the signer attesting its own submission
            // is not an independent reviewer; it counted as one, so one other
            // reviewer made a manifest CommunityVerified.
            if submission.signer_pubkey.as_deref() == Some(attestation.reviewer_pubkey.as_str()) {
                continue;
            }
            evidence.community_verified_count += 1;
            counted_attesters.push(attestation.clone());
        }

        Ok((evidence, counted_signer, counted_attesters))
    }

    /// Verify an ed25519 signature over [`signing_message`] for this program
    /// and content hash (MR-3).
    fn verify_signature(
        pubkey_b58: &str,
        signature_hex: &str,
        program_id: &str,
        content_hash: &str,
    ) -> bool {
        use ed25519_dalek::Signature;
        let Some(pk) = parse_verifying_key(pubkey_b58) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(signature_hex) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        pk.verify_strict(&signing_message(program_id, content_hash), &sig)
            .is_ok()
    }

    /// Durability snapshot (same pattern as SemanticGraphStore).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Restore a snapshot. A state file written before Round 29 has no
    /// corpus, refusals or revocations and loads with them empty. A corpus
    /// fixture that is not what it says it is (RG-1) fails the load — the
    /// registry's corpus is what the replay gate trusts.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let engine: Self = serde_json::from_str(json)?;
        engine
            .corpus
            .verify_integrity()
            .map_err(<serde_json::Error as serde::de::Error>::custom)?;
        Ok(engine)
    }
}

/// A base58 ed25519 public key, if `pubkey_b58` is one: 32 bytes that decode
/// to a valid curve point.
fn parse_verifying_key(pubkey_b58: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let decoded = bs58::decode(pubkey_b58).into_vec().ok()?;
    let bytes = <[u8; 32]>::try_from(decoded.as_slice()).ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
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

    /// An ed25519 signature over `message`, hex.
    fn sign(key: &SigningKey, message: &[u8]) -> String {
        hex::encode(key.sign(message).to_bytes())
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
                account_layouts: vec![],
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
        let message = sub.signing_message();
        ManifestSubmission {
            signature_hex: Some(sign(signer, &message)),
            ..sub
        }
    }

    fn signed_submission(program: &str, version: &str, signer: &SigningKey) -> ManifestSubmission {
        sign_manifest(manifest(program, "Test Protocol", version), signer)
    }

    /// A signed upgrade naming `previous` as the version it builds on (MR-2).
    fn signed_upgrade(
        program: &str,
        version: &str,
        previous: &str,
        signer: &SigningKey,
    ) -> ManifestSubmission {
        let mut m = manifest(program, "Test Protocol", version);
        m.version.previous_version_ref = Some(previous.to_string());
        sign_manifest(m, signer)
    }

    /// Round 40 (R39-CORE-IDENTITY-7): accept a first version `label` of
    /// `program`, signed by `signer` and pinned by its onboarding fixture, so
    /// the submission a test is about is an upgrade the gate replays against
    /// that fixture — and earns the tier its evidence computes rather than
    /// the first-manifest cap.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    fn accept_first_version(
        engine: &mut ManifestRegistryEngine,
        store: &mut SemanticGraphStore,
        program: &str,
        label: &str,
        signer: &SigningKey,
    ) {
        let core = GraphiteCore::new();
        let first = signed_submission(program, label, signer);
        let corpus = onboarding_corpus(&core, &first);
        let decision = engine
            .submit(store, first, Some((&corpus, &core)))
            .expect("first version accepted");
        assert!(
            matches!(
                decision,
                RegistryDecision::Accepted {
                    trust_tier: TrustTier::HeuristicInferred,
                    ..
                }
            ),
            "a first version is capped: {decision:?}"
        );
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

        // A valid program id: the registry runs the runtime's full validation
        // (MR-5), which refuses a malformed id before reaching discriminators.
        let mut m = manifest(NON_SEED, "Ambiguous", "v1.0");
        let mut second = m.instructions[0].clone();
        second.name = "SecondOp".to_string();
        second.discriminator = "0100".to_string(); // "01" is a proper prefix of "0100"
        m.instructions.push(second);
        let submission = sign_manifest(m, &signer);
        assert!(
            matches!(
                engine.submit(&mut store, submission, None),
                Err(RegistryError::InvalidManifest(reason)) if reason.contains("ambiguous discriminators")
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
            real_account_metas: vec![],
            state_diff: None,
        }
    }

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
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
        // Earning a tier is a promotion, so the P10 gate applies.
        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &submission);
        let decision = engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap();
        // Re-pinned in Round 40 (R39-CORE-IDENTITY-7): a FIRST version earned
        // OfficialManifest from its signature although its replay was against
        // fixtures recorded under it. It is capped at HeuristicInferred now;
        // the signature still counts (the evidence is recorded), and the
        // first upgrade replayed against this version's fixtures earns it.
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
                version_label: "v1.0".to_string(),
            }
        );
        let record = store
            .get("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
            .unwrap();
        assert_eq!(record.trust_tier, TrustTier::HeuristicInferred);
        assert!(record.evidence.has_signed_manifest);
        assert!(record.first_manifest_unvalidated);

        // Round 41 (D-30): from a reviewer who did not write v1.0's
        // fixtures; the same signer's upgrade stays capped.
        let upgrader = key(2);
        engine
            .register_reviewer(&pubkey_b58(&upgrader), 1000)
            .unwrap();
        let upgrade = signed_upgrade(
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "v1.1",
            "v1.0",
            &upgrader,
        );
        let corpus = onboarding_corpus(&core, &upgrade);
        let decision = engine
            .submit(&mut store, upgrade, Some((&corpus, &core)))
            .unwrap();
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::OfficialManifest,
                version_label: "v1.1".to_string(),
            }
        );
        // P7: the graph record's tier matches, computed not asserted.
        let record = store
            .get("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
            .unwrap();
        assert_eq!(record.trust_tier, TrustTier::OfficialManifest);
        assert!(record.evidence.has_signed_manifest);
        assert!(!record.first_manifest_unvalidated);
    }

    /// Round 36 (F-008): an accepted record carries what a third party needs
    /// to check it without the registry: the manifest, the signature that
    /// counted and the domain it was made under. Round 35's record kept the
    /// signer's key and no signature, so nothing in it could be checked.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn an_accepted_record_verifies_offline_and_a_tampered_one_does_not() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(1);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let submission = signed_submission(
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "v1.0",
            &signer,
        );
        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &submission);
        engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap();
        let record = engine.records().last().unwrap().clone();
        assert_eq!(record.verify_offline(), Ok(()));
        // It survives the persisted form.
        let back: RegistryRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(back.verify_offline(), Ok(()));

        let mut content = record.clone();
        content.manifest.as_mut().unwrap().instructions[0].name = "Other".to_string();
        assert!(content.verify_offline().unwrap_err().contains("hashes to"));
        let mut sig = record.clone();
        sig.signature_hex = Some(sign(
            &key(9),
            &signing_message(&record.program_id, &record.content_hash),
        ));
        assert!(sig
            .verify_offline()
            .unwrap_err()
            .contains("does not verify"));
        let mut gone = record.clone();
        gone.signature_hex = None;
        assert!(gone.verify_offline().is_err());
        let mut domain = record.clone();
        domain.signing_domain = Some("graphite-manifest-registry-v0".to_string());
        assert!(domain.verify_offline().is_err());
        // Round 38 (Round 37, V-5): what the record claims about its
        // signatures is held to them. Each of these left every signature
        // valid and passed.
        let mut tier = record.clone();
        tier.trust_tier = TrustTier::CommunityVerified;
        assert!(tier
            .verify_offline()
            .unwrap_err()
            .contains("CommunityVerified with 0 attester(s)"));
        let mut battle = record.clone();
        battle.trust_tier = TrustTier::BattleTested;
        assert!(battle.verify_offline().is_err());
        let mut source = record.clone();
        source.source = "community".to_string();
        assert!(source.verify_offline().unwrap_err().contains("source"));
        // A record from before Round 36 is unverifiable, and says so.
        let mut old = record;
        old.signing_domain = None;
        old.signature_hex = None;
        assert!(old.verify_offline().unwrap_err().contains("predates"));
    }

    #[test]
    fn registry_rejects_resource_exhaustion_manifest() {
        // 1000 instructions (cap 512) must be rejected BEFORE any hashing or
        // signing work — a clean resource-exhaustion guard, not an OOM.
        let mut m = manifest("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", "Huge", "v1");
        m.instructions = (0..1000)
            .map(|i| InstructionDef {
                account_layouts: vec![],
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
                optional: false,
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

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
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

        // Round 40: v1.0 first, so this v2.0 is a validated upgrade and its
        // tier is what its attestations earn (a first version is capped).
        accept_first_version(
            &mut engine,
            &mut store,
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
            "v1.0",
            &c,
        );
        let mut m = manifest(
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
            "Meteora",
            "v2.0",
        );
        m.version.previous_version_ref = Some("v1.0".to_string());
        let mut submission = ManifestSubmission {
            manifest: m,
            signer_pubkey: None,
            signature_hex: None,
            attestations: vec![],
        };
        let hash = submission.signing_message();
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
                signature_hex: sign(&c, b"tampered-hash"),
            },
            ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(&attacker),
                signature_hex: sign(&attacker, &hash),
            },
        ];

        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &submission);
        let decision = engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap();
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
    /// F11 (review of the A3-07 fix): the manifest in force, handed in again
    /// unchanged with evidence that earns a higher tier, is accepted; the
    /// same submission once more is a replay and refused.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn the_head_may_be_resubmitted_only_to_raise_its_tier() {
        const PROGRAM: &str = NON_SEED;
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let (a, b, c, d) = (key(61), key(62), key(63), key(64));
        engine.register_reviewer(&pubkey_b58(&a), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&b), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&c), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&d), 1000).unwrap();
        let core = GraphiteCore::new();

        // Round 40 (R39-CORE-IDENTITY-7): a first version's tier is capped
        // and more attestations of the same content cannot lift it — its
        // replay validated nothing, however many sign it. v0.9 is that first
        // version; resubmitted with two attesters it is refused as a replay.
        // Round 41 (D-30): signed by a reviewer who takes no part in v1.0, so
        // v1.0's replay of v0.9's fixtures is independent evidence.
        let first_version = signed_submission(PROGRAM, "v0.9", &d);
        let first_corpus = onboarding_corpus(&core, &first_version);
        engine
            .submit(
                &mut store,
                first_version.clone(),
                Some((&first_corpus, &core)),
            )
            .unwrap();
        let first_hash = first_version.signing_message();
        let mut first_attested = first_version;
        first_attested.attestations = [&b, &c]
            .into_iter()
            .map(|k| ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(k),
                signature_hex: sign(k, &first_hash),
            })
            .collect();
        assert!(matches!(
            engine.submit(&mut store, first_attested, Some((&first_corpus, &core))),
            Err(RegistryError::VersionAlreadyAccepted(_))
        ));

        // v1.0, an upgrade signed by one reviewer: OfficialManifest.
        let signed = signed_upgrade(PROGRAM, "v1.0", "v0.9", &a);
        let corpus = onboarding_corpus(&core, &signed);
        let first = engine
            .submit(&mut store, signed.clone(), Some((&corpus, &core)))
            .unwrap();
        assert!(matches!(
            first,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::OfficialManifest,
                ..
            }
        ));

        // The same content and label, now attested by two reviewers other
        // than its signer (W11: the signer does not attest itself).
        let hash = signed.signing_message();
        let mut attested = signed.clone();
        attested.attestations = [&b, &c]
            .into_iter()
            .map(|k| ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(k),
                signature_hex: sign(k, &hash),
            })
            .collect();
        let upgraded = engine
            .submit(&mut store, attested.clone(), Some((&corpus, &core)))
            .expect("more evidence for the head raises its tier");
        assert_eq!(
            upgraded,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::CommunityVerified,
                version_label: "v1.0".to_string(),
            }
        );

        // Nothing new: refused as a replay.
        assert!(matches!(
            engine.submit(&mut store, attested, Some((&corpus, &core))),
            Err(RegistryError::VersionAlreadyAccepted(_))
        ));
        assert!(matches!(
            engine.submit(&mut store, signed, Some((&corpus, &core))),
            Err(RegistryError::VersionAlreadyAccepted(_))
        ));
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
                first_manifest_unvalidated: false,
            })
            .unwrap();
    }

    const SYSTEM: &str = "11111111111111111111111111111111";
    const ACCT_A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const ACCT_B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
    /// A program with no shipped seed manifest, so a candidate for it actually
    /// takes effect in `with_candidate_manifest`.
    const NON_SEED: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";

    /// Give a program an earned tier inside a CORE's own graph, so the wallet
    /// profile's tier floor is not what decides every fixture's verdict.
    // Used only by the tests gated on a network-capable feature.
    #[cfg_attr(
        not(any(feature = "rpc", feature = "server", feature = "cli")),
        allow(dead_code)
    )]
    fn seed_tier(core: &mut GraphiteCore, program_id: &str) {
        core.seed_behavior(Behavior {
            program_id: program_id.to_string(),
            version: "v1.0".to_string(),
            expected_state_changes: vec!["debits accounts.from".to_string()],
            allowed_cpis: vec![],
            trust_tier: TrustTier::Unknown, // recomputed by append (P7)
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
        .expect("seed behavior");
    }

    /// One recorded fixture for `submission`'s program, taken under the
    /// manifest the submission would install — the minimum a first submission
    /// needs to clear the P10 gate. Mirrors what a real onboarding flow does:
    /// replay the program against the candidate manifest, pin what you saw.
    // Used only by the tests gated on a network-capable feature.
    #[cfg_attr(
        not(any(feature = "rpc", feature = "server", feature = "cli")),
        allow(dead_code)
    )]
    fn onboarding_corpus(core: &GraphiteCore, submission: &ManifestSubmission) -> RegressionCorpus {
        let program = submission.manifest.protocol.program_id.clone();
        let candidate_core = core
            .with_candidate_manifest(&submission.manifest)
            .expect("candidate core");
        let input = make_fixture_input(&program, "01", "transfer", &[], &[ACCT_A, ACCT_B]);
        let observed = candidate_core.verify(&input).expect("verify").approved;
        let mut corpus = RegressionCorpus::new();
        crate::regression_engine::record_fixture(&mut corpus, &input, observed, "onboarding");
        corpus
    }

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

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
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
        // Re-pinned in Round 40 (R39-CORE-IDENTITY-7): the registry's first
        // version of the program, so HeuristicInferred (was OfficialManifest).
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
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

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
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

        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &submission);
        let decision = engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap();
        // Re-pinned in Round 40 (R39-CORE-IDENTITY-7): a first version, so
        // HeuristicInferred (was OfficialManifest) — further still from the
        // BattleTested the document claims.
        assert!(matches!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
                ..
            }
        ));
        assert_eq!(
            store.get(SYSTEM).unwrap().trust_tier,
            TrustTier::HeuristicInferred
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
    fn a_first_submission_is_a_promotion_and_is_gated() {
        // This asserted the OPPOSITE until 2026-09-05: "a brand-new program is
        // not a promotion — accepted with no regression run". That made the
        // gate trivially avoidable. An attacker holding one registered
        // reviewer key did not need to defeat the regression gate; they only
        // needed a program with no prior record, and the first submission
        // enshrined it at OfficialManifest (or higher with attestations) with
        // no replay at all. Moving a program from no trust to some trust is
        // the largest step the ladder has, and it is now gated like any other.
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(22);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let submission = signed_submission(NON_SEED, "v1.0", &signer);
        let err = engine.submit(&mut store, submission, None).unwrap_err();
        assert!(
            matches!(err, RegistryError::RegressionGateBlocked(_)),
            "a first submission with no corpus must be gated, got {err:?}"
        );
    }

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn the_gate_replays_the_candidate_manifest_not_the_core_it_was_handed() {
        // Two things at once, because they are the same mechanism:
        //
        //   1. The gate must be PASSABLE, or it is just a refusal to onboard
        //      anything. A fixture recorded against the candidate manifest
        //      replays cleanly under it.
        //   2. The gate must replay the CANDIDATE. Replaying the core it was
        //      handed answers "does the manifest already installed still
        //      work?" — a question no submission can change, and therefore a
        //      gate that always passes.
        //
        // The test is only meaningful if the two cores actually disagree about
        // this input, so it asserts that first rather than assuming it.
        const PROGRAM: &str = NON_SEED;
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(23);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        // `TestOp` describes a debit of `accounts.from`, so it declares the
        // two accounts that description needs; the shared stub manifest
        // declares none, which L4 rightly refuses as inconsistent.
        let mut candidate = manifest(PROGRAM, "Test Protocol", "v1.0");
        candidate.instructions[0].accounts = [("from", true), ("to", false)]
            .into_iter()
            .map(|(name, is_signer)| AccountRoleDef {
                name: name.to_string(),
                role: "writable".to_string(),
                is_writable: true,
                is_signer,
                pda_seeds: vec![],
                expected_address: vec![],
                optional: false,
            })
            .collect();
        // What `debits accounts.from` is: a transfer. Since external review R2
        // an intent is compared with the instruction's class, and an
        // unclassed instruction is not something a `transfer` declares.
        candidate.instructions[0].risk_class = "transfer".to_string();
        let submission = sign_manifest(candidate, &signer);

        let mut base = GraphiteCore::new();
        // The program needs an earned tier or the wallet profile's tier floor
        // rejects it under BOTH manifests, and the test could not tell them
        // apart.
        seed_tier(&mut base, PROGRAM);
        let candidate_core = base
            .with_candidate_manifest(&submission.manifest)
            .expect("candidate core");
        // The instruction the candidate manifest declares (`TestOp`, "01").
        // Under the candidate it is a described instruction; without the
        // manifest the program is unknown, which is a different verdict. (An
        // UNDECLARED discriminator no longer tells the two apart: since the
        // 2026-09-29 audit (A3-04) an instruction a manifest does not describe
        // is refused like an unknown program's.)
        let input = make_fixture_input(PROGRAM, "01", "transfer", &[], &[ACCT_A, ACCT_B]);

        let candidate_result = candidate_core.verify(&input).expect("verify");
        let base_result = base.verify(&input).expect("verify");
        let under_candidate = candidate_result.approved;
        let under_base = base_result.approved;
        let layers = |r: &crate::verification::VerificationResult| {
            r.layers
                .iter()
                .map(|l| format!("{}:{:?}:{}", l.layer, l.status, l.reason))
                .collect::<Vec<_>>()
                .join("\n  ")
        };
        assert_ne!(
            under_candidate,
            under_base,
            "the candidate manifest must change this input's outcome, or the \
             test cannot tell which core the gate replayed\ncandidate:\n  {}\nbase:\n  {}",
            layers(&candidate_result),
            layers(&base_result)
        );

        let mut corpus = RegressionCorpus::new();
        crate::regression_engine::record_fixture(
            &mut corpus,
            &input,
            under_candidate,
            "onboarding",
        );

        let decision = engine
            .submit(&mut store, submission, Some((&corpus, &base)))
            .expect(
                "the gate replayed the core it was handed rather than the \
                 candidate manifest — the recorded outcome only holds under \
                 the candidate",
            );
        assert!(matches!(decision, RegistryDecision::Accepted { .. }));
    }

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn a_first_submission_whose_replay_fails_is_blocked() {
        // The gate has to be able to say no on a first submission too, or
        // requiring a corpus is theatre.
        const PROGRAM: &str = NON_SEED;
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(24);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let submission = signed_submission(PROGRAM, "v1.0", &signer);

        let base = GraphiteCore::new();
        let candidate_core = base
            .with_candidate_manifest(&submission.manifest)
            .expect("candidate core");
        let input = make_fixture_input(PROGRAM, "01", "transfer", &[], &[ACCT_A, ACCT_B]);
        let actual = candidate_core.verify(&input).expect("verify").approved;

        // Record the OPPOSITE of what the candidate manifest produces.
        let mut corpus = RegressionCorpus::new();
        crate::regression_engine::record_fixture(&mut corpus, &input, !actual, "onboarding");

        let err = engine
            .submit(&mut store, submission, Some((&corpus, &base)))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::RegressionGateBlocked(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_candidate_for_a_seed_program_leaves_the_registry_untouched() {
        // Accepting a submission for a seed program does not install its
        // manifest — seed-wins — so the manifest in force afterwards is still
        // the seed one, and that is what the gate must replay. A candidate
        // that DID take effect here would have the gate approve a submission
        // against behaviour that will never run.
        let core = GraphiteCore::new();
        let mut m = manifest(SYSTEM, "Impostor System Program", "v9.9");
        m.instructions[0].discriminator = "ff".to_string();
        let candidate_core = core
            .with_candidate_manifest(&m)
            .expect("a seed candidate is evaluable, just inert");
        let seed = candidate_core
            .registry()
            .get(SYSTEM)
            .expect("seed manifest must survive");
        assert_ne!(
            seed.protocol.name, "Impostor System Program",
            "a candidate must never displace a shipped seed manifest"
        );
    }

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn an_accepted_upgrade_replaces_the_manifest_that_reaches_verification() {
        // Found live 2026-09-05: submitting v2.0.0 printed ACCEPTED, recorded
        // the version and its lineage, and showed it on the dashboard — while
        // `verify` went on resolving instructions against v1.0.0 forever.
        // `merge_community` skips a program already in the registry, so
        // whichever manifest reached it first won permanently. A protocol
        // could never correct a manifest, including to TIGHTEN a rule.
        const PROGRAM: &str = NON_SEED;
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(31);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        let core = GraphiteCore::new();
        let v1 = signed_submission(PROGRAM, "v1.0", &signer);
        let corpus = onboarding_corpus(&core, &v1);
        engine
            .submit(&mut store, v1, Some((&corpus, &core)))
            .unwrap();

        let mut m2 = manifest(PROGRAM, "Renamed Protocol", "v2.0");
        m2.instructions[0].name = "SecondVersionOp".to_string();
        m2.version.previous_version_ref = Some("v1.0".to_string());
        // W12: an upgrade is held to the gate like a promotion; this one
        // changes no verdict the corpus pins, so it passes.
        assert!(matches!(
            engine.submit(&mut store, sign_manifest(m2.clone(), &signer), None),
            Err(RegistryError::RegressionGateBlocked(_))
        ));
        engine
            .submit(
                &mut store,
                sign_manifest(m2, &signer),
                Some((&corpus, &core)),
            )
            .expect("an upgrade that keeps every pinned verdict is accepted");

        // What actually reaches verification.
        let mut registry = crate::manifest::load_seed_manifests();
        let merged = registry.merge_community(&engine.manifests_in_force());
        assert_eq!(merged, 1, "one program, one current manifest");
        let in_force = registry.get(PROGRAM).expect("merged manifest");
        assert_eq!(
            in_force.instructions[0].name, "SecondVersionOp",
            "the accepted upgrade must be the manifest in force, not the one it replaced"
        );

        // P4: the append-only log still holds both versions.
        assert_eq!(
            engine
                .records()
                .iter()
                .filter(|r| r.program_id == PROGRAM)
                .count(),
            2
        );
    }

    /// W11 (external review, verified 2026-10-03): a signer attesting its own
    /// submission is not an independent reviewer.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn the_signer_does_not_attest_its_own_submission() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let (a, b, c) = (key(71), key(72), key(73));
        engine.register_reviewer(&pubkey_b58(&a), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&b), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&c), 1000).unwrap();
        let core = GraphiteCore::new();
        // Round 40: an upgrade, so the tier is what the evidence earns.
        // Round 41 (D-30): v0.9 from a reviewer with no part in v1.0.
        accept_first_version(&mut engine, &mut store, NON_SEED, "v0.9", &c);
        let mut submission = signed_upgrade(NON_SEED, "v1.0", "v0.9", &a);
        let hash = submission.signing_message();
        submission.attestations = [&a, &b]
            .into_iter()
            .map(|k| ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(k),
                signature_hex: sign(k, &hash),
            })
            .collect();
        let corpus = onboarding_corpus(&core, &submission);
        let decision = engine
            .submit(&mut store, submission, Some((&corpus, &core)))
            .unwrap();
        assert_eq!(
            decision,
            RegistryDecision::Accepted {
                trust_tier: TrustTier::OfficialManifest,
                version_label: "v1.0".to_string(),
            },
            "one independent attester, not two"
        );
    }

    /// W12 (external review, verified 2026-10-03): a second reviewer's v2 that
    /// retags v1's control instruction as a transfer, at the same tier, was
    /// accepted with no replay and became the manifest in force. The gate now
    /// runs on every upgrade, at the tier the registry computes — here the
    /// document declares none, and replaying at Unknown let it through too.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn a_loosening_upgrade_at_the_same_tier_is_refused_by_the_replay() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let (a, b) = (key(81), key(82));
        engine.register_reviewer(&pubkey_b58(&a), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&b), 1000).unwrap();
        let core = GraphiteCore::new();

        // The accounts `debits accounts.from` needs (a stub that declares
        // none is refused by L4 as inconsistent under any class).
        let accounts: Vec<AccountRoleDef> = [("from", true), ("to", false)]
            .into_iter()
            .map(|(name, is_signer)| AccountRoleDef {
                name: name.to_string(),
                role: "writable".to_string(),
                is_writable: true,
                is_signer,
                pda_seeds: vec![],
                expected_address: vec![],
                optional: false,
            })
            .collect();
        let mut v1 = manifest(NON_SEED, "Guarded", "v1.0");
        v1.instructions[0].accounts = accounts.clone();
        v1.instructions[0].risk_class = "authority".to_string();
        let v1 = sign_manifest(v1, &a);
        let corpus = onboarding_corpus(&core, &v1);
        assert!(
            !corpus.all()[0].expected_approved,
            "precondition: v1 refuses its control instruction"
        );
        engine
            .submit(&mut store, v1, Some((&corpus, &core)))
            .unwrap();

        let mut v2 = manifest(NON_SEED, "Guarded", "v2.0");
        v2.version.previous_version_ref = Some("v1.0".to_string());
        v2.instructions[0].accounts = accounts;
        v2.instructions[0].risk_class = "transfer".to_string();
        assert_eq!(v2.trust_tier, "", "the document declares no tier");
        // Precondition: at the tier the runtime would give it, v2 approves the
        // fixture v1 pinned as refused.
        let mut at_runtime_tier = v2.clone();
        at_runtime_tier.trust_tier = "OfficialManifest".to_string();
        let input = &corpus.all()[0].input;
        assert!(
            core.with_candidate_manifest(&at_runtime_tier)
                .unwrap()
                .verify(input)
                .unwrap()
                .approved,
            "precondition: the loosened manifest approves at its runtime tier"
        );
        assert!(matches!(
            engine.submit(&mut store, sign_manifest(v2, &b), Some((&corpus, &core))),
            Err(RegistryError::RegressionGateBlocked(_))
        ));
        assert_eq!(engine.manifests_in_force()[0].version.label, "v1.0");
    }

    #[test]
    fn a_candidate_that_fails_schema_validation_is_an_error() {
        // A manifest the runtime loader would refuse must never be replayed as
        // though it could take effect — that would gate a submission against
        // behaviour that cannot exist.
        let core = GraphiteCore::new();
        let mut m = manifest(NON_SEED, "Bad", "v1.0");
        m.instructions = vec![];
        assert!(core.with_candidate_manifest(&m).is_err());
    }

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn version_lineage_is_append_only_and_linked() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(30);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();

        let program = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
        let core = GraphiteCore::new();
        let v1 = signed_submission(program, "v1.0", &signer);
        let corpus = onboarding_corpus(&core, &v1);
        // v1.0 earns a tier (a promotion, so gated); v2.0 earns the same tier
        // and, as an upgrade of a manifest in force, is gated too (W12).
        engine
            .submit(&mut store, v1, Some((&corpus, &core)))
            .unwrap();
        engine
            .submit(
                &mut store,
                signed_upgrade(program, "v2.0", "v1.0", &signer),
                Some((&corpus, &core)),
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

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn deterministic_same_submission_same_decision() {
        // Two independent engines: the same submission to the SAME engine is
        // a replay and is refused (`VersionAlreadyAccepted`, A3-07).
        let signer = key(50);
        let engine_with_reviewer = || {
            let mut engine = ManifestRegistryEngine::new();
            engine
                .register_reviewer(&pubkey_b58(&signer), 1000)
                .unwrap();
            engine
        };
        let mut engine = engine_with_reviewer();
        let mut engine_b = engine_with_reviewer();
        let program = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";

        let mut store_a = SemanticGraphStore::new();
        let mut store_b = SemanticGraphStore::new();
        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &signed_submission(program, "v1.0", &signer));
        let d1 = engine
            .submit(
                &mut store_a,
                signed_submission(program, "v1.0", &signer),
                Some((&corpus, &core)),
            )
            .unwrap();
        let d2 = engine_b
            .submit(
                &mut store_b,
                signed_submission(program, "v1.0", &signer),
                Some((&corpus, &core)),
            )
            .unwrap();
        assert_eq!(d1, d2, "same submission ⇒ same decision (P2)");
    }

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
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
        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &signed_submission(program, "v1.0", &signer));
        engine
            .submit(
                &mut store,
                signed_submission(program, "v1.0", &signer),
                Some((&corpus, &core)),
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

    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
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
        let core = GraphiteCore::new();
        let community_sub = signed_submission(community_program, "v1.0", &signer);
        let seed_sub = signed_submission(seed_program, "v1.0", &signer);
        let community_corpus = onboarding_corpus(&core, &community_sub);
        let seed_corpus = onboarding_corpus(&core, &seed_sub);
        engine
            .submit(&mut store, community_sub, Some((&community_corpus, &core)))
            .unwrap();
        engine
            .submit(&mut store, seed_sub, Some((&seed_corpus, &core)))
            .unwrap();

        let mut registry = load_seed_manifests();
        let seed_disc = registry
            .get(seed_program)
            .expect("seed manifest present")
            .instructions
            .first()
            .map(|i| i.discriminator.clone());

        let merged = registry.merge_community(&engine.manifests_in_force());
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

    // ── Round 29 (audit 2026-10-20): MR-1 … MR-6, G-3 ──────────────────────

    fn guarded_accounts() -> Vec<AccountRoleDef> {
        [("from", true), ("to", false)]
            .into_iter()
            .map(|(name, is_signer)| AccountRoleDef {
                name: name.to_string(),
                role: "writable".to_string(),
                is_writable: true,
                is_signer,
                pda_seeds: vec![],
                expected_address: vec![],
                optional: false,
            })
            .collect()
    }

    /// MR-1: the gate replays the registry's OWN corpus. v1's refusal fixture
    /// is replayed against a loosening v2 even though the corpus v2's
    /// submitter hands in leaves it out (and carries a fixture of its own
    /// that v2 passes).
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn a_submission_cannot_drop_a_fixture_the_registry_holds() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let (a, b) = (key(91), key(92));
        engine.register_reviewer(&pubkey_b58(&a), 1000).unwrap();
        engine.register_reviewer(&pubkey_b58(&b), 1000).unwrap();
        let core = GraphiteCore::new();

        let mut v1 = manifest(NON_SEED, "Guarded", "v1.0");
        v1.instructions[0].accounts = guarded_accounts();
        v1.instructions[0].risk_class = "authority".to_string();
        let v1 = sign_manifest(v1, &a);
        let corpus = onboarding_corpus(&core, &v1);
        assert!(!corpus.all()[0].expected_approved, "precondition");
        engine
            .submit(&mut store, v1, Some((&corpus, &core)))
            .unwrap();
        assert_eq!(
            engine.regression_corpus().fixtures_for(NON_SEED).len(),
            1,
            "the accepted version's fixture joins the registry's corpus"
        );

        let mut v2 = manifest(NON_SEED, "Guarded", "v2.0");
        v2.version.previous_version_ref = Some("v1.0".to_string());
        v2.instructions[0].accounts = guarded_accounts();
        v2.instructions[0].risk_class = "transfer".to_string();
        let v2 = sign_manifest(v2, &b);
        // The submitter's own corpus: one fixture v2 replays cleanly (an
        // instruction v2 does not describe, refused under it), and NOT v1's.
        let candidate = core.with_candidate_manifest(&v2.manifest).unwrap();
        let other = make_fixture_input(NON_SEED, "02", "transfer", &[], &[ACCT_A, ACCT_B]);
        let outcome = candidate.verify(&other).unwrap().approved;
        let mut partial = RegressionCorpus::new();
        crate::regression_engine::record_fixture(&mut partial, &other, outcome, "submitter");
        assert!(matches!(
            engine.submit(&mut store, v2, Some((&partial, &core))),
            Err(RegistryError::RegressionGateBlocked(_))
        ));
        assert_eq!(engine.manifests_in_force()[0].version.label, "v1.0");
        assert_eq!(engine.refused().len(), 1, "the refusal is recorded");

        // The registry's corpus survives its state file, and a state file
        // written before it existed still loads.
        let restored = ManifestRegistryEngine::from_json(&engine.to_json().unwrap()).unwrap();
        assert_eq!(restored.regression_corpus().len(), 1);
        assert_eq!(restored.refused().len(), 1);
        let legacy = r#"{"reviewers":{},"records":[]}"#;
        let old = ManifestRegistryEngine::from_json(legacy).expect("pre-Round-29 state loads");
        assert!(old.regression_corpus().is_empty() && old.refused().is_empty());
    }

    /// MR-2: a submission must build on the version in force, and a version
    /// the gate refused is never taken again — not even after the fixture
    /// that pinned it is retired.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn lineage_is_enforced_and_a_refused_version_stays_refused() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(93);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let core = GraphiteCore::new();
        let v1 = signed_submission(NON_SEED, "v1.0", &signer);
        let corpus = onboarding_corpus(&core, &v1);
        engine
            .submit(&mut store, v1, Some((&corpus, &core)))
            .unwrap();

        // No previous_version_ref, then the wrong one: both refused.
        for previous in [None, Some("v0.9")] {
            let mut m = manifest(NON_SEED, "Test Protocol", "v2.0");
            m.version.previous_version_ref = previous.map(str::to_string);
            let err = engine
                .submit(
                    &mut store,
                    sign_manifest(m, &signer),
                    Some((&corpus, &core)),
                )
                .unwrap_err();
            assert!(
                matches!(err, RegistryError::StaleLineage { ref head, .. } if head.as_deref() == Some("v1.0")),
                "{err:?}"
            );
        }
        engine
            .submit(
                &mut store,
                signed_upgrade(NON_SEED, "v2.0", "v1.0", &signer),
                Some((&corpus, &core)),
            )
            .unwrap();
        // An older version signed against v1, handed in after v2: refused.
        assert!(matches!(
            engine.submit(
                &mut store,
                signed_upgrade(NON_SEED, "v1.5", "v1.0", &signer),
                Some((&corpus, &core)),
            ),
            Err(RegistryError::StaleLineage { .. })
        ));

        // A version the gate refuses: its fixture pins the opposite outcome.
        let v3 = signed_upgrade(NON_SEED, "v3.0", "v2.0", &signer);
        let candidate = core.with_candidate_manifest(&v3.manifest).unwrap();
        let input = make_fixture_input(NON_SEED, "01", "stake", &[], &[ACCT_A, ACCT_B]);
        let actual = candidate.verify(&input).unwrap().approved;
        let mut pinning = RegressionCorpus::new();
        crate::regression_engine::record_fixture(&mut pinning, &input, !actual, "pin");
        assert!(matches!(
            engine.submit(&mut store, v3.clone(), Some((&pinning, &core))),
            Err(RegistryError::RegressionGateBlocked(_))
        ));
        // The pinning fixture was never accepted into the registry's corpus,
        // and even with a clean corpus the refused version is not retried.
        assert!(matches!(
            engine.submit(&mut store, v3, Some((&corpus, &core))),
            Err(RegistryError::VersionPreviouslyRefused(_))
        ));
    }

    /// MR-3: a signature over the bare content hash — what any wallet's
    /// `signMessage` over that string produces — no longer verifies; the
    /// signed message is domain-tagged and names the program.
    #[test]
    fn a_signature_over_the_bare_hash_does_not_verify() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let signer = key(94);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let mut sub = signed_submission(NON_SEED, "v1.0", &signer);
        sub.signature_hex = Some(sign(&signer, sub.content_hash().as_bytes()));
        assert!(matches!(
            engine.submit(&mut store, sub.clone(), None),
            Err(RegistryError::InvalidSignature(_))
        ));
        let hash = sub.content_hash();
        let mut expected = b"graphite-manifest-registry-v1\0".to_vec();
        expected.extend_from_slice(NON_SEED.as_bytes());
        expected.push(0);
        expected.extend_from_slice(hash.as_bytes());
        assert_eq!(sub.signing_message(), expected);
        assert_eq!(signing_message(NON_SEED, &hash), expected);
        // The same signature does not carry over to another program.
        let good = signed_submission(NON_SEED, "v1.0", &signer);
        assert!(ManifestRegistryEngine::verify_signature(
            &pubkey_b58(&signer),
            good.signature_hex.as_deref().unwrap(),
            NON_SEED,
            &hash
        ));
        assert!(!ManifestRegistryEngine::verify_signature(
            &pubkey_b58(&signer),
            good.signature_hex.as_deref().unwrap(),
            SYSTEM,
            &hash
        ));
    }

    /// MR-4: the content hash is over canonical JSON — keys sorted at every
    /// level, no insignificant whitespace — so it does not depend on the
    /// order the struct declares its fields in.
    #[test]
    fn the_content_hash_covers_canonical_json() {
        let m = manifest(NON_SEED, "Test Protocol", "v1.0");
        let canonical = canonical_manifest_json(&m);
        // Top-level keys in byte order (the struct declares `protocol` and
        // `version` BEFORE `instructions`), the nested objects likewise.
        assert!(
            canonical.starts_with(r#"{"graphite_manifest_version":"1.0","instructions":[{"accounts":[],"allowed_cpis":[],"discriminator":"01""#),
            "{canonical}"
        );
        let positions: Vec<usize> = [
            "\"graphite_manifest_version\"",
            "\"instructions\"",
            "\"protocol\"",
            "\"trust_tier\"",
            "\"version\":{",
        ]
        .iter()
        .map(|k| canonical.find(k).unwrap())
        .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{canonical}");
        assert!(
            canonical.contains(
                r#""version":{"effective_from_slot":0,"label":"v1.0","previous_version_ref":null}"#
            ),
            "{canonical}"
        );
        assert!(
            !canonical.contains(": ") && !canonical.contains(", ") && !canonical.contains('\n')
        );
        use sha2::{Digest, Sha256};
        let sub = ManifestSubmission {
            manifest: m,
            signer_pubkey: None,
            signature_hex: None,
            attestations: vec![],
        };
        assert_eq!(
            sub.content_hash(),
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
    }

    /// MR-5: the registry runs the runtime's own validation, so a manifest the
    /// loader would refuse is refused at submission — rules the registry's
    /// partial copy did not have.
    #[test]
    fn a_submission_the_runtime_would_refuse_is_refused() {
        let mut bogus_class = manifest(NON_SEED, "T", "v1");
        bogus_class.instructions[0].risk_class = "multisig_execution".to_string();
        let mut non_hex = manifest(NON_SEED, "T", "v1");
        non_hex.instructions[0].discriminator = "zz".to_string();
        let mut self_derived = manifest(NON_SEED, "T", "v1");
        self_derived.instructions[0].accounts = guarded_accounts();
        self_derived.instructions[0].accounts[0].pda_seeds = vec!["{account_0}".to_string()];
        for m in [bogus_class, non_hex, self_derived] {
            assert!(crate::manifest::validate_manifest(&m).is_err());
            assert!(matches!(
                ManifestRegistryEngine::validate_manifest(&m),
                Err(RegistryError::InvalidManifest(_))
            ));
        }
    }

    /// MR-6: a reviewer key must be a usable ed25519 key, and a revoked
    /// reviewer's attestations stop counting where the tier is recomputed —
    /// in force and on the graph.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn a_revoked_reviewer_stops_counting() {
        let mut engine = ManifestRegistryEngine::new();
        assert!(matches!(
            engine.register_reviewer("reviewerPubkey1", 1000),
            Err(RegistryError::MalformedReviewerPubkey(_))
        ));
        assert!(matches!(
            engine.register_reviewer(&bs58::encode([1u8; 31]).into_string(), 1000),
            Err(RegistryError::MalformedReviewerPubkey(_))
        ));
        let mut store = SemanticGraphStore::new();
        let (signer, a, b, first) = (key(95), key(96), key(97), key(94));
        for k in [&signer, &a, &b, &first] {
            engine.register_reviewer(&pubkey_b58(k), 1000).unwrap();
        }
        // Round 40: an upgrade, so the tier is what the evidence earns.
        accept_first_version(&mut engine, &mut store, NON_SEED, "v0.9", &first);
        let mut sub = signed_upgrade(NON_SEED, "v1.0", "v0.9", &signer);
        let message = sub.signing_message();
        sub.attestations = [&a, &b]
            .into_iter()
            .map(|k| ReviewerAttestation {
                reviewer_pubkey: pubkey_b58(k),
                signature_hex: sign(k, &message),
            })
            .collect();
        let core = GraphiteCore::new();
        let corpus = onboarding_corpus(&core, &sub);
        engine
            .submit(&mut store, sub, Some((&corpus, &core)))
            .unwrap();
        assert_eq!(
            engine.manifests_in_force()[0].trust_tier,
            "CommunityVerified"
        );
        assert!(!engine.records().last().unwrap().first_manifest_unvalidated);
        assert_eq!(
            store.get(NON_SEED).unwrap().trust_tier,
            TrustTier::CommunityVerified
        );

        assert_eq!(
            engine.revoke_reviewer(&mut store, &pubkey_b58(&b)).unwrap(),
            1
        );
        assert_eq!(
            engine.manifests_in_force()[0].trust_tier,
            "OfficialManifest"
        );
        assert_eq!(
            store.get(NON_SEED).unwrap().trust_tier,
            TrustTier::OfficialManifest
        );
        assert!(matches!(
            engine.register_reviewer(&pubkey_b58(&b), 1000),
            Err(RegistryError::ReviewerRevoked(_))
        ));
        assert!(matches!(
            engine.revoke_reviewer(&mut store, &pubkey_b58(&b)),
            Err(RegistryError::UnknownReviewer(_))
        ));
        // A revoked signer's new submission is refused outright.
        engine
            .revoke_reviewer(&mut store, &pubkey_b58(&signer))
            .unwrap();
        assert!(matches!(
            engine.submit(
                &mut store,
                signed_upgrade(NON_SEED, "v2.0", "v1.0", &signer),
                Some((&corpus, &core))
            ),
            Err(RegistryError::ReviewerRevoked(_))
        ));
        // The revocation survives the state file.
        let restored = ManifestRegistryEngine::from_json(&engine.to_json().unwrap()).unwrap();
        assert_eq!(restored.revoked_reviewers().len(), 2);
    }

    /// G-3: accepting a manifest keeps the program's operator-seeded graph
    /// evidence; it used to append a record carrying registry evidence only.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn a_registry_acceptance_keeps_operator_evidence() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        store
            .append(Behavior {
                program_id: NON_SEED.to_string(),
                version: "operator".to_string(),
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                trust_tier: TrustTier::Unknown,
                evidence: BehaviorEvidence {
                    has_signed_manifest: true,
                    battle_tested_tx_count: 5000,
                    simulation_match_count: 9,
                    ..Default::default()
                },
                quarantined: false,
                quarantine_reason: None,
                first_manifest_unvalidated: false,
            })
            .unwrap();
        let signer = key(98);
        engine
            .register_reviewer(&pubkey_b58(&signer), 1000)
            .unwrap();
        let core = GraphiteCore::new();
        let sub = signed_submission(NON_SEED, "v1.0", &signer);
        let corpus = onboarding_corpus(&core, &sub);
        engine
            .submit(&mut store, sub, Some((&corpus, &core)))
            .unwrap();
        let latest = store.get(NON_SEED).unwrap();
        assert_eq!(latest.version, "v1.0");
        assert_eq!(latest.evidence.battle_tested_tx_count, 5000);
        assert_eq!(latest.evidence.simulation_match_count, 9);
        assert_eq!(latest.trust_tier, TrustTier::BattleTested);
    }

    /// Round 40 (R39-CORE-IDENTITY-7, owner decision option 4): a FIRST
    /// manifest's replay is against fixtures recorded under it, so it proves
    /// nothing about it; its tier is capped at HeuristicInferred — in the
    /// record, in the manifest in force and in the graph — however much
    /// registry evidence it carries, until an upgrade passes the gate against
    /// fixtures it did not write, or measured volume earns more.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    #[test]
    fn a_first_manifest_is_capped_until_independent_evidence_lifts_it() {
        let mut engine = ManifestRegistryEngine::new();
        let mut store = SemanticGraphStore::new();
        let (signer, a, b) = (key(111), key(112), key(113));
        for k in [&signer, &a, &b] {
            engine.register_reviewer(&pubkey_b58(k), 1000).unwrap();
        }
        let core = GraphiteCore::new();
        // Signed and attested by two other reviewers: CommunityVerified by
        // its evidence.
        let attested = |mut sub: ManifestSubmission| {
            let message = sub.signing_message();
            sub.attestations = [&a, &b]
                .into_iter()
                .map(|k| ReviewerAttestation {
                    reviewer_pubkey: pubkey_b58(k),
                    signature_hex: sign(k, &message),
                })
                .collect();
            sub
        };
        let first = attested(signed_submission(NON_SEED, "v1.0", &signer));
        let corpus = onboarding_corpus(&core, &first);
        assert_eq!(
            engine
                .submit(&mut store, first, Some((&corpus, &core)))
                .unwrap(),
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
                version_label: "v1.0".to_string(),
            }
        );
        let record = engine.records().last().unwrap().clone();
        assert!(record.first_manifest_unvalidated);
        assert_eq!(record.trust_tier, TrustTier::HeuristicInferred);
        assert_eq!(record.attesters.len(), 2, "the evidence is recorded");
        assert_eq!(record.verify_offline(), Ok(()));
        assert_eq!(
            engine.manifests_in_force()[0].trust_tier,
            "HeuristicInferred"
        );
        let graph = store.get(NON_SEED).unwrap().clone();
        assert!(graph.first_manifest_unvalidated);
        assert_eq!(graph.evidence.community_verified_count, 2);
        assert_eq!(graph.trust_tier, TrustTier::HeuristicInferred);

        // A record that claims more than its flag allows is not the record
        // the registry wrote.
        let mut tampered = record.clone();
        tampered.trust_tier = TrustTier::CommunityVerified;
        assert!(tampered
            .verify_offline()
            .unwrap_err()
            .contains("capped at HeuristicInferred"));

        // Operator-asserted evidence does not lift it; a seed carries the
        // flag forward (only the registry's independent replay clears it).
        let seeded = |store: &mut SemanticGraphStore, evidence: BehaviorEvidence| {
            store
                .append(Behavior {
                    program_id: NON_SEED.to_string(),
                    version: "operator".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    trust_tier: TrustTier::Unknown,
                    evidence,
                    quarantined: false,
                    quarantine_reason: None,
                    first_manifest_unvalidated: false,
                })
                .unwrap();
            store.get(NON_SEED).unwrap().trust_tier
        };
        let mut seeded_store = store.clone();
        assert_eq!(
            seeded(
                &mut seeded_store,
                BehaviorEvidence {
                    has_signed_manifest: true,
                    community_verified_count: 5,
                    simulation_match_count: 10,
                    battle_tested_tx_count: 999,
                }
            ),
            TrustTier::HeuristicInferred
        );
        // Measured volume at the BattleTested threshold (a census-backed
        // record) earns its tier as it always did.
        assert_eq!(
            seeded(
                &mut seeded_store,
                BehaviorEvidence {
                    has_signed_manifest: true,
                    battle_tested_tx_count: 1_000,
                    ..Default::default()
                }
            ),
            TrustTier::BattleTested
        );
        assert!(
            seeded_store
                .get(NON_SEED)
                .unwrap()
                .first_manifest_unvalidated
        );

        // The cap survives the graph's and the registry's state files.
        let restored = SemanticGraphStore::from_json(&store.to_json().unwrap()).unwrap();
        assert_eq!(
            restored.get(NON_SEED).unwrap().trust_tier,
            TrustTier::HeuristicInferred
        );
        let engine_restored =
            ManifestRegistryEngine::from_json(&engine.to_json().unwrap()).unwrap();
        assert_eq!(
            engine_restored.manifests_in_force()[0].trust_tier,
            "HeuristicInferred"
        );

        // An upgrade with its own fixtures only — every fixture an earlier
        // version pinned retired by the operator — validated nothing either.
        let mut retired = engine.clone();
        let mut retired_store = store.clone();
        let pinned: Vec<String> = retired
            .regression_corpus()
            .fixtures_for(NON_SEED)
            .iter()
            .map(|f| f.content_hash.clone())
            .collect();
        for h in &pinned {
            assert!(retired.deprecate_regression_fixture(h));
        }
        let mut m = manifest(NON_SEED, "Test Protocol", "v1.1");
        m.version.previous_version_ref = Some("v1.0".to_string());
        m.instructions[0].discriminator = "02".to_string();
        let alone = attested(sign_manifest(m, &signer));
        let mut own = RegressionCorpus::new();
        let input = make_fixture_input(NON_SEED, "02", "transfer", &[], &[ACCT_A, ACCT_B]);
        let observed = core
            .with_candidate_manifest(&alone.manifest)
            .unwrap()
            .verify(&input)
            .unwrap()
            .approved;
        crate::regression_engine::record_fixture(&mut own, &input, observed, "own");
        assert_eq!(
            retired
                .submit(&mut retired_store, alone, Some((&own, &core)))
                .unwrap(),
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
                version_label: "v1.1".to_string(),
            }
        );

        // Round 41 (D-30): the same reviewers' upgrade replays only fixtures
        // they wrote themselves, so it validates nothing and stays capped.
        // Until then this lifted the cap.
        let mut same_keys = engine.clone();
        let mut same_keys_store = store.clone();
        let upgrade = attested(signed_upgrade(NON_SEED, "v1.1", "v1.0", &signer));
        let corpus = onboarding_corpus(&core, &upgrade);
        assert_eq!(
            same_keys
                .submit(&mut same_keys_store, upgrade, Some((&corpus, &core)))
                .unwrap(),
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
                version_label: "v1.1".to_string(),
            }
        );
        assert!(
            same_keys
                .records()
                .last()
                .unwrap()
                .first_manifest_unvalidated
        );
        assert_eq!(
            same_keys.manifests_in_force()[0].trust_tier,
            "HeuristicInferred"
        );
        // One shared key is enough to keep it capped: a new signer with one
        // of v1.0's attesters still replays that attester's fixtures.
        let (signer2, c) = (key(114), key(115));
        for k in [&signer2, &c] {
            engine.register_reviewer(&pubkey_b58(k), 1000).unwrap();
        }
        let partly = {
            let mut sub = signed_upgrade(NON_SEED, "v1.1", "v1.0", &signer2);
            let message = sub.signing_message();
            sub.attestations = [&a, &c]
                .into_iter()
                .map(|k| ReviewerAttestation {
                    reviewer_pubkey: pubkey_b58(k),
                    signature_hex: sign(k, &message),
                })
                .collect();
            sub
        };
        let corpus = onboarding_corpus(&core, &partly);
        assert_eq!(
            engine
                .clone()
                .submit(&mut store.clone(), partly, Some((&corpus, &core)))
                .unwrap(),
            RegistryDecision::Accepted {
                trust_tier: TrustTier::HeuristicInferred,
                version_label: "v1.1".to_string(),
            }
        );

        // The upgrade the gate replays against v1.0's fixtures, from keys
        // that did not write them: the cap is lifted, and the evidence earns
        // its tier.
        let d = key(116);
        engine.register_reviewer(&pubkey_b58(&d), 1000).unwrap();
        let upgrade = {
            let mut sub = signed_upgrade(NON_SEED, "v1.1", "v1.0", &signer2);
            let message = sub.signing_message();
            sub.attestations = [&c, &d]
                .into_iter()
                .map(|k| ReviewerAttestation {
                    reviewer_pubkey: pubkey_b58(k),
                    signature_hex: sign(k, &message),
                })
                .collect();
            sub
        };
        let corpus = onboarding_corpus(&core, &upgrade);
        assert_eq!(
            engine
                .submit(&mut store, upgrade, Some((&corpus, &core)))
                .unwrap(),
            RegistryDecision::Accepted {
                trust_tier: TrustTier::CommunityVerified,
                version_label: "v1.1".to_string(),
            }
        );
        assert!(!engine.records().last().unwrap().first_manifest_unvalidated);
        assert_eq!(
            engine.manifests_in_force()[0].trust_tier,
            "CommunityVerified"
        );
        let graph = store.get(NON_SEED).unwrap();
        assert!(!graph.first_manifest_unvalidated);
        assert_eq!(graph.trust_tier, TrustTier::CommunityVerified);
    }
}
