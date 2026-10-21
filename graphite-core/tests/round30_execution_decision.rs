//! Round 30 (G-01): a verdict says what it permits, and only one value
//! permits signing.
//!
//! `approved: true` came back for a transaction nothing had simulated: with
//! no RPC the pipeline approves on static analysis and earned evidence and
//! says so only in `scope.unobserved_codes` (`not_simulated`). A `/verify`
//! caller, an SDK user, a library embedder or a `graphite verify && sign`
//! shell gate that read `approved` signed it. The agent guard's residual
//! policy refused it; nothing else did.
//!
//! The Core now decides, once, from the finished verdict: `decision` is
//! `executable_approved` only for an approval bound to exact bytes that
//! Graphite itself simulated, with nothing unobserved beyond the two
//! inherent residuals, risk Clear, policy Approved and no layer failed.
//! `executable` mirrors it. These tests drive every path that must NOT be
//! executable — no RPC, descriptive, unparsed, refused — pin the rule
//! itself field by field, and pin that a deserialized verdict cannot be
//! edited into permission. The RPC paths (clean → executable, failed →
//! blocked, unobtainable → inconclusive) are in
//! `audit_2026_10_20_simulation_gate.rs`.

use graphite_core::confidence_engine::TrustTier;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    execution_decision, ExecutionDecision, GraphiteCore, LayerStatus, ProposedIntent, RiskFinding,
    UnobservedCode, VerificationInput, VerificationResult, VerificationScope,
};

const SYSTEM: &str = "11111111111111111111111111111111";

fn corpus_entry(name: &str) -> serde_json::Value {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("corpus entry {name}"))
        .clone()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The lowest bar a fresh core's described transfer (0.44,
/// OfficialManifest) clears, so an approval here is the pipeline's, and a
/// non-executable decision is about evidence, never the score.
fn official_floor() -> WalletProfile {
    WalletProfile::Custom {
        min_confidence: 0.40,
        min_trust_tier: TrustTier::OfficialManifest,
    }
}

/// The corpus's legacy transfer, described faithfully; `artifact` decides
/// whether its bytes are supplied.
fn transfer(artifact: Option<Vec<u8>>, profile: WalletProfile) -> VerificationInput {
    let entry = corpus_entry("legacy_single_transfer");
    let keys = strings(&entry["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: Some(transfer_data(2_000_000)),
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: artifact,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn corpus_bytes() -> Vec<u8> {
    bytes(&corpus_entry("legacy_single_transfer")["raw"])
}

fn verify(input: &VerificationInput) -> VerificationResult {
    GraphiteCore::new().verify(input).expect("verify")
}

/// No RPC: the bytes are supplied, parsed, located — and never executed.
/// The pipeline approves (that is unchanged); the verdict does not permit
/// signing.
#[test]
fn an_approval_nothing_simulated_is_analysis_only() {
    let r = verify(&transfer(Some(corpus_bytes()), official_floor()));
    assert!(r.approved, "control: approved ({})", r.summary);
    assert!(r.scope.is_artifact_bound());
    assert!(r
        .scope
        .unobserved_codes()
        .contains(&UnobservedCode::NotSimulated));
    assert_eq!(r.decision, ExecutionDecision::AnalysisOnly);
    assert!(!r.executable);
    assert!(!r.is_executable());
}

/// No artifact at all: an approval of a description binds to nothing.
#[test]
fn a_descriptive_approval_is_analysis_only() {
    let r = verify(&transfer(None, official_floor()));
    assert!(r.approved, "control: approved ({})", r.summary);
    assert!(matches!(r.scope, VerificationScope::Descriptive { .. }));
    assert_eq!(r.decision, ExecutionDecision::AnalysisOnly);
    assert!(!r.executable);
}

/// Bytes that are not a Solana transaction: L2 fails and the verdict is
/// refused — blocked, not analysis.
#[test]
fn unparseable_bytes_are_blocked() {
    let r = verify(&transfer(Some(vec![0xff; 40]), official_floor()));
    assert!(!r.approved, "{}", r.summary);
    assert!(r
        .scope
        .unobserved_codes()
        .contains(&UnobservedCode::ArtifactUnparsed));
    assert_eq!(r.decision, ExecutionDecision::Blocked);
    assert!(!r.executable);
}

/// A refusal by the policy threshold (Treasury needs far more than a fresh
/// program's 0.44): blocked.
#[test]
fn a_policy_refusal_is_blocked() {
    let r = verify(&transfer(Some(corpus_bytes()), WalletProfile::Treasury));
    assert!(!r.approved);
    assert_eq!(r.decision, ExecutionDecision::Blocked);
    assert!(!r.executable);
}

/// The wire spelling, and `instruction_bind_key` (R-M10) beside the
/// deprecated `content_hash`, same value.
#[test]
fn the_decision_is_on_the_wire() {
    let r = verify(&transfer(Some(corpus_bytes()), official_floor()));
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["decision"], "analysis_only");
    assert_eq!(v["executable"], false);
    assert_eq!(v["instruction_bind_key"], v["content_hash"]);
    assert!(!r.instruction_bind_key.is_empty());
    let refused = serde_json::to_value(verify(&transfer(
        Some(corpus_bytes()),
        WalletProfile::Treasury,
    )))
    .unwrap();
    assert_eq!(refused["decision"], "blocked");
}

/// What the rule would make of this approval had Graphite simulated it
/// cleanly: the same verdict, with the scope a clean simulation produces.
fn as_if_simulated(mut r: VerificationResult) -> VerificationResult {
    if let VerificationScope::ArtifactBound {
        simulated,
        unobserved,
        unobserved_codes,
        ..
    } = &mut r.scope
    {
        *simulated = true;
        let keep: Vec<usize> = unobserved_codes
            .iter()
            .enumerate()
            .filter(|(_, c)| c.inherent())
            .map(|(i, _)| i)
            .collect();
        *unobserved = keep.iter().map(|i| unobserved[*i].clone()).collect();
        *unobserved_codes = keep.iter().map(|i| unobserved_codes[*i]).collect();
    } else {
        panic!("artifact-bound expected");
    }
    r
}

/// The rule, one field at a time: starting from the one shape that is
/// executable, each change below takes the permission away.
#[test]
fn the_rule_takes_permission_away_field_by_field() {
    let base = as_if_simulated(verify(&transfer(Some(corpus_bytes()), official_floor())));
    assert_eq!(
        execution_decision(&base),
        ExecutionDecision::ExecutableApproved,
        "control: a simulated, artifact-bound approval with inherent residuals only"
    );

    let mut residual_variants = Vec::new();
    for code in UnobservedCode::ALL.iter().filter(|c| !c.inherent()) {
        let mut r = base.clone();
        if let VerificationScope::ArtifactBound {
            unobserved,
            unobserved_codes,
            ..
        } = &mut r.scope
        {
            unobserved.push(format!("{} (test)", code.as_str()));
            unobserved_codes.push(*code);
        }
        residual_variants.push((code.as_str().to_string(), r));
    }
    for (code, r) in &residual_variants {
        assert_eq!(
            execution_decision(r),
            ExecutionDecision::AnalysisOnly,
            "a non-inherent residual ({code}) must take executable away"
        );
    }

    let mut not_simulated = base.clone();
    if let VerificationScope::ArtifactBound { simulated, .. } = &mut not_simulated.scope {
        *simulated = false;
    }
    let mut prose_without_code = base.clone();
    if let VerificationScope::ArtifactBound { unobserved, .. } = &mut prose_without_code.scope {
        unobserved.push("something unobserved with no code".to_string());
    }
    let mut layer_failed = base.clone();
    layer_failed.layers[0].status = LayerStatus::Failed;
    let mut risk_not_clear = base.clone();
    risk_not_clear.risk_verdict.status = "Blocked".to_string();
    let mut policy_rejected = base.clone();
    policy_rejected.policy_verdict = "Rejected".to_string();
    let mut descriptive = base.clone();
    descriptive.scope = VerificationScope::Descriptive {
        unobserved: vec!["no artifact".to_string()],
        unobserved_codes: vec![UnobservedCode::NoArtifact],
    };
    for (what, r) in [
        ("simulated: false", &not_simulated),
        ("prose without a code", &prose_without_code),
        ("a failed layer", &layer_failed),
        ("risk not Clear", &risk_not_clear),
        ("policy Rejected", &policy_rejected),
        ("descriptive scope", &descriptive),
    ] {
        assert_eq!(
            execution_decision(r),
            ExecutionDecision::AnalysisOnly,
            "{what} must take executable away"
        );
    }

    // Refusals: inconclusive only when every finding is missing evidence.
    let refuse = |patterns: &[&str]| {
        let mut r = base.clone();
        r.approved = false;
        r.risk_verdict.status = "Blocked".to_string();
        r.risk_verdict.findings = patterns
            .iter()
            .map(|p| RiskFinding {
                pattern: p.to_string(),
                reason: "test".to_string(),
            })
            .collect();
        execution_decision(&r)
    };
    assert_eq!(
        refuse(&["VerificationIncomplete"]),
        ExecutionDecision::Inconclusive
    );
    assert_eq!(
        refuse(&["VerificationIncomplete", "DrainerPattern"]),
        ExecutionDecision::Blocked,
        "a definite finding beside missing evidence is a block"
    );
    assert_eq!(refuse(&["SimulationFailed"]), ExecutionDecision::Blocked);
    assert_eq!(
        refuse(&[]),
        ExecutionDecision::Blocked,
        "a policy or structural refusal"
    );
}

/// A verdict read back from JSON and edited to claim permission is not
/// executable: `is_executable` recomputes the rule.
#[test]
fn an_edited_verdict_is_not_executable() {
    let r = verify(&transfer(Some(corpus_bytes()), official_floor()));
    let mut v = serde_json::to_value(&r).unwrap();
    v["decision"] = "executable_approved".into();
    v["executable"] = true.into();
    let forged: VerificationResult = serde_json::from_value(v).unwrap();
    assert_eq!(forged.decision, ExecutionDecision::ExecutableApproved);
    assert!(
        !forged.is_executable(),
        "not_simulated is still on the scope"
    );

    // A record from before Round 30 has no decision: blocked, never
    // permission.
    let mut v = serde_json::to_value(&r).unwrap();
    v.as_object_mut().unwrap().remove("decision");
    v.as_object_mut().unwrap().remove("executable");
    let old: VerificationResult = serde_json::from_value(v).unwrap();
    assert_eq!(old.decision, ExecutionDecision::Blocked);
    assert!(!old.is_executable());

    // An unknown decision does not deserialize at all.
    let mut v = serde_json::to_value(&r).unwrap();
    v["decision"] = "approved".into();
    assert!(serde_json::from_value::<VerificationResult>(v).is_err());

    // And the consistent executable shape IS executable — the check is not
    // vacuous.
    let mut ok = as_if_simulated(r);
    ok.decision = execution_decision(&ok);
    ok.executable = ok.decision == ExecutionDecision::ExecutableApproved;
    assert!(ok.is_executable());
    ok.executable = false;
    assert!(!ok.is_executable(), "executable: false is not permission");
}

/// `graphite verify` attaches no RPC: its approvals are analysis only, and
/// it exits 3 for them — not 0, which a `verify && sign` gate reads as go.
#[cfg(feature = "cli")]
#[test]
fn the_cli_does_not_exit_zero_on_an_analysis_only_approval() {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("graphite-r30-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("input.json");
    let input = serde_json::to_value(transfer(Some(corpus_bytes()), official_floor())).unwrap();
    std::fs::write(&file, input.to_string()).unwrap();
    let run = |profile: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_graphite"))
            .env("GRAPHITE_DATA_DIR", dir.join("data"))
            .env("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"))
            .env("GRAPHITE_ALLOW_PERMISSIVE_PROFILES", "1")
            .args(["verify", "--file"])
            .arg(&file)
            .args(profile)
            .output()
            .unwrap()
    };
    let out = run(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{e}: {stdout}\n{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(v["approved"], true, "control: {}", v["summary"]);
    assert_eq!(v["decision"], "analysis_only");
    assert_eq!(out.status.code(), Some(3), "analysis_only exits 3");

    let out = run(&["--profile", "treasury"]);
    assert_eq!(out.status.code(), Some(1), "a refusal exits 1");
    std::fs::remove_dir_all(&dir).ok();
}
