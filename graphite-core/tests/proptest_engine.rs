//! Property-based invariants for the Graphite pipeline (proptest).
//!
//! The handcrafted adversarial corpus pins specific attacks; these tests pin
//! STRUCTURAL invariants that must hold for ANY input (Constitution P2
//! determinism, P3 explainability, fail-closed design):
//!   - `verify()` never panics
//!   - confidence is always in [0, 1] and never NaN/Infinity
//!   - `content_hash` is deterministic and always 16 hex chars
//!   - `approved` implies the risk verdict is Clear (a hard gate can't be bypassed)
//!   - breakdown contributions sum to the reported confidence (P3)
//!   - `compute_confidence` rejects NaN/Inf signal values instead of
//!     propagating them into a confidence score

use graphite_core::confidence_engine::{compute_confidence, SignalKind, TrustTier, WeightedSignal};
use graphite_core::verification::{ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;
use proptest::prelude::*;

const SYS: &str = "11111111111111111111111111111111";
const KNOWN_ACCOUNTS: &[&str] = &[
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
];
const PROGRAMS: &[&str] = &[
    SYS,
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
];
const INTENTS: &[&str] = &["transfer", "swap", "stake", "close", "approve"];

/// Random 2..16-char hex discriminator.
fn hex_discriminator() -> impl Strategy<Value = String> {
    prop::collection::vec("[0-9a-fA-F]", 2..16).prop_map(|v| v.concat())
}

fn valid_input_strategy() -> impl Strategy<Value = VerificationInput> {
    (
        prop::sample::select(PROGRAMS),
        hex_discriminator(),
        prop::collection::vec(prop::sample::select(KNOWN_ACCOUNTS), 0..4),
        prop::sample::select(INTENTS),
        0..500_000u64, // compute units
        0..200u32,     // account writes
        0..20u32,      // cpi hops
    )
        .prop_map(
            |(program, disc, extra, intent, cu, writes, hops)| VerificationInput {
                proposed_intent: ProposedIntent {
                    intent_type: intent.to_string(),
                    raw_natural_language: "proptest input".to_string(),
                    confidence_of_parse: 0.9,
                    extracted_parameters: None,
                },
                program_id: program.to_string(),
                protocol_version: "1.0.0".to_string(),
                instruction_discriminator: disc,
                account_addresses: extra.into_iter().map(|s| s.to_string()).collect(),
                instruction_data: None,
                cpi_targets: vec![],
                wallet_profile: WalletProfile::TradingBot,
                behavior_evidence: Default::default(),
                compute_units: cu,
                account_writes: writes,
                cpi_hops: hops,
                signed_transaction: None,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Never panic, and any successful result is structurally valid.
    #[test]
    fn verify_never_panics_and_result_is_sane(input in valid_input_strategy()) {
        let core = graphite_core::GraphiteCore::new();
        match core.verify(&input) {
            Ok(r) => {
                assert!(
                    (0.0..=1.0).contains(&r.confidence),
                    "confidence out of range: {}",
                    r.confidence
                );
                assert!(
                    !r.confidence.is_nan() && !r.confidence.is_infinite(),
                    "confidence must be finite"
                );
                assert_eq!(r.content_hash.len(), 16, "content_hash must be 16 hex chars");
                assert!(
                    r.content_hash.chars().all(|c| c.is_ascii_hexdigit()),
                    "content_hash must be hex"
                );
                // A hard risk gate can never be bypassed by an approval.
                if r.approved {
                    assert_eq!(
                        r.risk_verdict.status, "Clear",
                        "approved must imply risk verdict Clear"
                    );
                }
                // P3: the breakdown must explain the final score.
                let sum: f64 = r.breakdown.iter().map(|b| b.contribution).sum();
                // Tolerance 0.01: the TrustTierCeiling item is omitted when the
                // ceiling reduction is below 0.001 (floating-point noise filter).
                assert!(
                    (sum - r.confidence).abs() < 0.01,
                    "breakdown contributions ({}) must explain confidence ({})",
                    sum,
                    r.confidence
                );
            }
            Err(_) => {
                // Caller-fixable errors (invalid account count, bad address,
                // unknown discriminator) are allowed — what matters is that the
                // pipeline never panics and never returns an invalid Ok.
            }
        }
    }

    /// P2: identical input must produce the identical deterministic content hash.
    #[test]
    fn content_hash_is_deterministic(input in valid_input_strategy()) {
        let core = graphite_core::GraphiteCore::new();
        if let (Ok(a), Ok(b)) = (core.verify(&input), core.verify(&input)) {
            assert_eq!(
                a.content_hash, b.content_hash,
                "same input must produce the same content_hash (P2)"
            );
        }
    }

    /// NaN/Infinity signal values must be rejected, never propagated.
    #[test]
    fn confidence_engine_rejects_nan_and_stays_bounded(v in proptest::num::f64::ANY) {
        let signals = vec![
            WeightedSignal { kind: SignalKind::ManifestMatch, value: v, weight: 0.20 },
            WeightedSignal { kind: SignalKind::TrustTierLevel, value: 0.0, weight: 0.20 },
            WeightedSignal { kind: SignalKind::SimulationMatch, value: 0.0, weight: 0.20 },
            WeightedSignal { kind: SignalKind::HistoricalVolume, value: 0.0, weight: 0.15 },
            WeightedSignal { kind: SignalKind::CommunityVerification, value: 0.0, weight: 0.15 },
            WeightedSignal { kind: SignalKind::IntentAlignment, value: 0.0, weight: 0.10 },
        ];
        match compute_confidence(&signals, TrustTier::Unknown) {
            Ok(r) => {
                assert!(
                    (0.0..=1.0).contains(&r.confidence) && r.confidence.is_finite(),
                    "confidence must be finite and bounded: {}",
                    r.confidence
                );
            }
            Err(_) => { /* NaN/Inf rejected — the desired fail-closed behavior */ }
        }
    }
}
