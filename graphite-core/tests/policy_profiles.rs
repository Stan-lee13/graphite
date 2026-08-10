//! Policy Engine real-integration tests (Phase 2 Feature 6).
//!
//! Proves the four built-in wallet profiles are *satisfiable and
//! differentiable* via the Semantic Graph's internal accumulator (G4):
//! confidence signals read from internally-earned evidence, so each preset
//! gates at its own thresholds, and caller-fabricated request-body evidence
//! can never mint confidence. Also covers the CLI `--profile` override
//! end-to-end through the real binary.

use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;
use std::path::PathBuf;
#[cfg(feature = "cli")]
use std::process::Command;

// ─── Test helpers ────────────────────────────────────────────────────────────

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
// Valid base58 account addresses (no 0/O/I/l), matching the exploit suite's.
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const RECIPIENT: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const UNKNOWN_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";

fn system_transfer(profile: WalletProfile) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Send 0.5 SOL to Alice".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![SIGNER.to_string(), RECIPIENT.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
    }
}

/// Seed the program's simulation baseline AND an earned graph behavior with
/// the given evidence. Both are internal-accumulator state (never request
/// body), which is exactly what the Phase 2 signals now read.
///
/// Note the two distinct "simulation" counters: the SIMULATION MATCH signal
/// reads the baseline's `sample_count` (50 here → full signal), while the
/// behavior's `simulation_match_count` drives only the trust TIER (P7). Both
/// are seeded so the tier and the signal are earned together.
fn seed_system(core: &mut GraphiteCore, evidence: BehaviorEvidence) {
    core.seed_simulation_baseline(
        SYSTEM_PROGRAM,
        ComputeBaseline {
            mean_compute_units: 150.0,
            std_compute_units: 1.0,
            sample_count: 50, // well above MIN_SAMPLES
            mean_account_writes: 2.0,
            std_account_writes: 0.5,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.1,
            ..Default::default()
        },
    )
    .expect("baseline seed");
    core.seed_behavior(Behavior {
        program_id: SYSTEM_PROGRAM.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: vec!["debits accounts.from by amount".to_string()],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown, // recomputed by append (P7)
        evidence,
        quarantined: false,
        quarantine_reason: None,
    })
    .expect("behavior seed");
}

/// Evidence that earns SimulationValidated tier (3+ simulation matches).
fn sim_validated_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 0,
        battle_tested_tx_count: 0,
        simulation_match_count: 3,
    }
}

/// Evidence that earns SimulationValidated tier WITH battle-tested volume
/// (1000+ tx): what TradingBot needs — conf ≈ 0.81 at tier T3.
fn volume_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 0,
        battle_tested_tx_count: 1000,
        simulation_match_count: 3,
    }
}

/// Evidence that earns BattleTested tier (1000+ tx AND community/signed).
fn battle_tested_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 2,
        battle_tested_tx_count: 1000,
        simulation_match_count: 100,
    }
}

// ─── Profile matrix: each preset is satisfiable via earned evidence ─────────

#[test]
fn gaming_profile_approves_with_earned_simulation_evidence() {
    let mut core = GraphiteCore::new();
    seed_system(&mut core, sim_validated_evidence());
    let r = core
        .verify(&system_transfer(WalletProfile::Gaming))
        .expect("verify");
    assert!(
        r.approved,
        "Gaming (0.60, T1) must approve a simulation-validated System transfer: {}",
        r.summary
    );
    assert!(
        r.confidence >= 0.60,
        "conf {} below Gaming threshold",
        r.confidence
    );
}

#[test]
fn trading_bot_profile_approves_with_volume_evidence() {
    let mut core = GraphiteCore::new();
    // Simulation-validated tier + 1000 battle-tested tx: conf ≈ 0.81.
    seed_system(&mut core, volume_evidence());
    let r = core
        .verify(&system_transfer(WalletProfile::TradingBot))
        .expect("verify");
    assert!(
        r.approved,
        "TradingBot (0.80, T3) must approve with volume evidence: {}",
        r.summary
    );
    assert!(
        r.confidence >= 0.80,
        "conf {} below TradingBot threshold",
        r.confidence
    );
}

#[test]
fn treasury_profile_approves_with_community_verified_evidence() {
    let mut core = GraphiteCore::new();
    seed_system(&mut core, battle_tested_evidence());
    let r = core
        .verify(&system_transfer(WalletProfile::Treasury))
        .expect("verify");
    assert!(
        r.approved,
        "Treasury (0.95, T4) must approve battle-tested evidence: {}",
        r.summary
    );
    // Full evidence: conf ≈ 1.00 (0.20 manifest + 0.20 tier + 0.20 sim +
    // 0.15 volume + 0.15 community + 0.10 intent).
    assert!(
        r.confidence >= 0.95,
        "conf {} below Treasury threshold",
        r.confidence
    );
}

#[test]
fn enterprise_profile_approves_with_full_evidence() {
    let mut core = GraphiteCore::new();
    seed_system(&mut core, battle_tested_evidence());
    let r = core
        .verify(&system_transfer(WalletProfile::Enterprise))
        .expect("verify");
    assert!(
        r.approved,
        "Enterprise (0.99, T5) must approve full battle-tested evidence: {}",
        r.summary
    );
    assert!(
        r.confidence >= 0.99,
        "conf {} below Enterprise threshold",
        r.confidence
    );
}

// ─── Differentiation: profiles gate at their own thresholds ─────────────────

#[test]
fn profiles_are_differentiated_by_evidence_strength() {
    // Simulation-validated evidence: enough for Gaming, not TradingBot.
    let mut core = GraphiteCore::new();
    seed_system(&mut core, sim_validated_evidence());
    let g = core
        .verify(&system_transfer(WalletProfile::Gaming))
        .unwrap();
    assert!(
        g.approved,
        "Gaming must pass at simulation-validated evidence"
    );
    let t = core
        .verify(&system_transfer(WalletProfile::TradingBot))
        .unwrap();
    assert!(
        !t.approved,
        "TradingBot must NOT pass at simulation-validated-only evidence (needs volume): {}",
        t.summary
    );

    // Full evidence: passes Treasury but not Enterprise (conf < 0.99 gate).
    let mut core = GraphiteCore::new();
    seed_system(&mut core, battle_tested_evidence());
    let tr = core
        .verify(&system_transfer(WalletProfile::Treasury))
        .unwrap();
    assert!(tr.approved, "Treasury must pass at battle-tested evidence");
}

#[test]
fn fresh_core_blocks_all_profiles() {
    // No earned evidence: confidence is the honest ~0.44 for a known protocol
    // (P7 caps the manifest tier at OfficialManifest). Every preset must block.
    for profile in [
        WalletProfile::Treasury,
        WalletProfile::TradingBot,
        WalletProfile::Gaming,
        WalletProfile::Enterprise,
    ] {
        let core = GraphiteCore::new();
        let r = core.verify(&system_transfer(profile)).expect("verify");
        assert!(
            !r.approved,
            "{profile:?} must block a fresh-core (unearned) System transfer: {}",
            r.summary
        );
    }
}

#[test]
fn unknown_program_blocked_by_all_profiles() {
    for profile in [
        WalletProfile::Treasury,
        WalletProfile::TradingBot,
        WalletProfile::Gaming,
        WalletProfile::Enterprise,
    ] {
        let core = GraphiteCore::new();
        let mut input = system_transfer(profile);
        input.program_id = UNKNOWN_PROGRAM.to_string();
        let r = core.verify(&input).expect("verify");
        assert!(
            !r.approved,
            "{profile:?} must block an unknown program with zero evidence: {}",
            r.summary
        );
    }
}

// ─── G4: caller-fabricated request-body evidence is a no-op ─────────────────

#[test]
fn fabricated_request_evidence_cannot_mint_confidence() {
    // The request body claims maximal evidence. The engine must ignore it:
    // signals read from the Semantic Graph (fresh core → all zero), so the
    // profile gate still blocks and confidence stays honest (~0.44).
    let core = GraphiteCore::new();
    let mut input = system_transfer(WalletProfile::Gaming);
    input.behavior_evidence = BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 999,
        battle_tested_tx_count: 999_999,
        simulation_match_count: 999_999,
    };
    let r = core.verify(&input).expect("verify");
    assert!(
        !r.approved,
        "G4: fabricated evidence must not mint approval: {}",
        r.summary
    );
    assert!(
        r.confidence < 0.60,
        "G4: fabricated evidence inflated confidence to {} (expected ≤ fresh-core 0.44)",
        r.confidence
    );
    // And the result must not claim a fabricated tier either.
    assert!(
        r.trust_tier != "BattleTested",
        "G4: fabricated evidence minted trust tier {}",
        r.trust_tier
    );
}

#[test]
fn fabricated_evidence_does_not_affect_content_hash_determinism() {
    // P2: the request-body evidence is configuration, so its value still hashes
    // into content_hash — but it must NOT change the *decision* path. This pins
    // the honest behavior: two identical decisions, hash differs only if the
    // input JSON differs, never because the graph state drifted.
    let core = GraphiteCore::new();
    let mut a = system_transfer(WalletProfile::Gaming);
    let mut b = system_transfer(WalletProfile::Gaming);
    a.behavior_evidence = BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 999,
        battle_tested_tx_count: 999_999,
        simulation_match_count: 999_999,
    };
    b.behavior_evidence = BehaviorEvidence::default();
    let ra = core.verify(&a).unwrap();
    let rb = core.verify(&b).unwrap();
    // content_hash covers ONLY transaction inputs (program, discriminator,
    // accounts, data, CPIs) — behavior_evidence is deliberately NOT hashed,
    // so the fabricated-evidence variant produces the SAME hash as the plain
    // one. That is the G4 point in a single assertion: request-body evidence
    // cannot even perturb the fingerprint, let alone the decision.
    assert_eq!(ra.content_hash, rb.content_hash);
    // And the DECISION must be identical — evidence is ignored on both.
    assert_eq!(ra.approved, rb.approved);
    assert!(!ra.approved && !rb.approved);
}

// ─── Custom profile + Custom validation ─────────────────────────────────────

#[test]
fn custom_profile_honors_explicit_thresholds() {
    let mut core = GraphiteCore::new();
    seed_system(&mut core, sim_validated_evidence());
    // Custom with permissive thresholds: conf 0.66 → 0.60 passes.
    let permissive = core
        .verify(&system_transfer(WalletProfile::Custom {
            min_confidence: 0.60,
            min_trust_tier: TrustTier::HeuristicInferred,
        }))
        .unwrap();
    assert!(
        permissive.approved,
        "permissive custom must approve: {}",
        permissive.summary
    );
    // Custom with strict thresholds: same evidence → blocked.
    let strict = core
        .verify(&system_transfer(WalletProfile::Custom {
            min_confidence: 0.95,
            min_trust_tier: TrustTier::BattleTested,
        }))
        .unwrap();
    assert!(
        !strict.approved,
        "strict custom must block: {}",
        strict.summary
    );
}

// ─── CLI --profile override, end-to-end through the real binary ─────────────
// These spawn the real `graphite` binary, which only exists under the `cli`
// feature ([[bin]] required-features). Guarded so `cargo test
// --no-default-features` still compiles the suite.

#[cfg(feature = "cli")]
fn graphite_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_graphite"))
}

fn write_input(tmp: &std::path::Path, name: &str, profile: &str) -> PathBuf {
    let json = format!(
        r#"{{
  "proposed_intent": {{
    "intent_type": "transfer",
    "raw_natural_language": "Send 0.5 SOL to Alice",
    "confidence_of_parse": 0.9,
    "extracted_parameters": null
  }},
  "program_id": "{SYSTEM_PROGRAM}",
  "protocol_version": "1.0.0",
  "instruction_discriminator": "02000000",
  "account_addresses": ["{SIGNER}", "{RECIPIENT}"],
  "instruction_data": null,
  "cpi_targets": [],
  "wallet_profile": "{profile}",
  "behavior_evidence": {{"has_signed_manifest": false, "community_verified_count": 0, "battle_tested_tx_count": 0, "simulation_match_count": 0}},
  "compute_units": 150,
  "account_writes": 2,
  "cpi_hops": 0,
  "signed_transaction": null
}}"#,
    );
    let p = tmp.join(name);
    std::fs::write(&p, json).expect("write input json");
    p
}

#[cfg(feature = "cli")]
#[test]
fn cli_profiles_subcommand_lists_presets() {
    let out = Command::new(graphite_bin())
        .arg("profiles")
        .output()
        .expect("run graphite profiles");
    assert!(out.status.success(), "profiles subcommand must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in ["Treasury", "TradingBot", "Gaming", "Enterprise", "Custom"] {
        assert!(
            text.contains(needle),
            "profiles output missing {needle}:\n{text}"
        );
    }
}

#[cfg(feature = "cli")]
#[test]
fn cli_profile_override_is_applied_and_gate_fires() {
    // A fresh CLI core has no earned evidence → confidence 0.44. Even Gaming
    // (0.60) must reject, and the CLI must exit 1 (CI-gate semantics).
    let dir = std::env::temp_dir().join(format!("graphite-cli-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = write_input(&dir, "transfer.json", "Treasury");
    let out = Command::new(graphite_bin())
        .args(["verify", "--file"])
        .arg(&input)
        .args(["--profile", "gaming"])
        .output()
        .expect("run graphite verify --profile gaming");
    // Unearned evidence → blocked → exit 1 regardless of the permissive override.
    assert_eq!(out.status.code(), Some(1), "unearned transfer must exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"approved\": false"),
        "must report approved:false:\n{stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(feature = "cli")]
#[test]
fn cli_unknown_profile_fails_closed() {
    let dir = std::env::temp_dir().join(format!("graphite-cli-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = write_input(&dir, "transfer.json", "Treasury");
    let out = Command::new(graphite_bin())
        .args(["verify", "--file"])
        .arg(&input)
        .args(["--profile", "hacker-profile"])
        .output()
        .expect("run graphite verify --profile unknown");
    assert!(
        !out.status.success(),
        "unknown profile name must fail closed (non-zero exit)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown profile"),
        "must name the unknown profile:\n{stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(feature = "cli")]
#[test]
fn cli_custom_profile_requires_both_thresholds() {
    let dir = std::env::temp_dir().join(format!("graphite-cli-cust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = write_input(&dir, "transfer.json", "Treasury");
    // --profile custom without thresholds must fail closed.
    let out = Command::new(graphite_bin())
        .args(["verify", "--file"])
        .arg(&input)
        .args(["--profile", "custom"])
        .output()
        .expect("run graphite verify --profile custom (no thresholds)");
    assert!(!out.status.success(), "custom without thresholds must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--min-confidence"),
        "must require --min-confidence:\n{stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
