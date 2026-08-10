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
//!
//! The input strategy is DELIBERATELY hostile (wider than the previous
//! pre-validated-only generator): malformed base58 program IDs, non-hex and
//! empty discriminators, arbitrary byte instruction data, every wallet
//! profile, oversized account lists, and extreme compute-unit values. If the
//! engine panics, or produces a structurally invalid Ok, on ANY of these the
//! invariant is broken.

use graphite_core::confidence_engine::{compute_confidence, SignalKind, TrustTier, WeightedSignal};
use graphite_core::verification::{ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;
use proptest::prelude::*;

const SYS: &str = "11111111111111111111111111111111";
const SPL: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const RAYDIUM: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const UNKNOWN: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

const VALID_ACCOUNTS: &[&str] = &[
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
    "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
];

/// Hostile program IDs: real ones, a truncated one, garbage, and a
/// lookalike (last char swapped).
fn program_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(SYS.to_string()),
        Just(SPL.to_string()),
        Just(RAYDIUM.to_string()),
        Just(JUPITER.to_string()),
        Just(UNKNOWN.to_string()),
        Just("111111111111111111111111111111".to_string()), // truncated
        Just("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV5".to_string()), // lookalike
        Just("not-a-valid-address!!!".to_string()),         // garbage
        prop::collection::vec(prop::char::range('0', 'z'), 5..20)
            .prop_map(|c| c.into_iter().collect()),
    ]
}

/// Random 0..16-char hex discriminator (may be empty or odd-length).
fn hex_discriminator() -> impl Strategy<Value = String> {
    prop::collection::vec("[0-9a-fA-F]", 0..16).prop_map(|v| v.concat())
}

/// Hostile discriminators: real selectors, valid-but-different hex,
/// non-hex garbage, uppercase, empty.
fn discriminator() -> impl Strategy<Value = String> {
    prop_oneof![
        hex_discriminator(),
        Just("02000000".to_string()),
        Just("03".to_string()),
        Just("bb64".to_string()), // truncated prefix of Jupiter's route_v2
        Just("bb64facc31c4af14".to_string()),
        Just("GGGGGGGG".to_string()), // non-hex
        Just("".to_string()),
        Just("0X09".to_string()), // 0X casing confusion
    ]
}

/// Hostile account lists: valid, empty, duplicated, and malformed entries.
fn accounts() -> impl Strategy<Value = Vec<String>> {
    prop_oneof![
        prop::collection::vec(prop::sample::select(VALID_ACCOUNTS), 0..6)
            .prop_map(|v| v.into_iter().map(str::to_string).collect()),
        Just(vec![UNKNOWN.to_string()]),   // unknown account key
        Just(vec!["nope".to_string(); 5]), // garbage accounts
        Just(vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
                .to_string();
            70
        ]), // over the 64 cap
        prop::collection::vec(prop::char::range('!', '~'), 3..8)
            .prop_map(|c| vec![c.into_iter().collect::<String>()]),
    ]
}

/// Arbitrary instruction data (may be None, empty, or up to 64 bytes of
/// arbitrary bytes — including a case that looks like a known discriminator).
fn instruction_data() -> impl Strategy<Value = Option<Vec<u8>>> {
    prop_oneof![
        Just(None),
        Just(Some(vec![])),
        prop::collection::vec(proptest::num::u8::ANY, 1..64).prop_map(Some),
        Just(Some(vec![0x02, 0x00, 0x00, 0x00])),
    ]
}

/// Every wallet profile, including adversarial Custom thresholds.
fn wallet_profile() -> impl Strategy<Value = WalletProfile> {
    prop_oneof![
        Just(WalletProfile::Treasury),
        Just(WalletProfile::Enterprise),
        Just(WalletProfile::Gaming),
        Just(WalletProfile::TradingBot),
        (0.0f64..=1.0).prop_map(|c| WalletProfile::Custom {
            min_confidence: c,
            min_trust_tier: TrustTier::Unknown,
        }),
        (0.0f64..=1.0).prop_map(|c| WalletProfile::Custom {
            min_confidence: c,
            min_trust_tier: TrustTier::BattleTested,
        }),
    ]
}

fn valid_input_strategy() -> impl Strategy<Value = VerificationInput> {
    (
        program_id(),
        discriminator(),
        accounts(),
        instruction_data(),
        wallet_profile(),
        0..=u64::MAX, // compute units — includes absurd values
        0..=u32::MAX, // account writes
        0..200u32,    // cpi hops
    )
        .prop_map(
            |(program, disc, accounts, data, profile, cu, writes, hops)| VerificationInput {
                proposed_intent: ProposedIntent {
                    intent_type: "transfer".to_string(),
                    raw_natural_language: "proptest input".to_string(),
                    confidence_of_parse: 0.9,
                    extracted_parameters: None,
                },
                program_id: program,
                protocol_version: "1.0.0".to_string(),
                instruction_discriminator: disc,
                account_addresses: accounts,
                instruction_data: data,
                cpi_targets: vec![],
                wallet_profile: profile,
                behavior_evidence: Default::default(),
                compute_units: cu,
                account_writes: writes,
                cpi_hops: hops,
                signed_transaction: None,
                transaction_instructions: vec![],
                cpi_trace: None,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

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
                // Every reported divergence must be JSON-serializable (finite).
                if let Some(d) = r.simulation_divergence {
                    assert!(d.is_finite(), "simulation_divergence must be finite, got {}", d);
                }
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

    /// Discriminator matching must never accept a truncated prefix of a
    /// known discriminator (the impersonation bypass): route_v2's real
    /// discriminator is "bb64facc31c4af14", and nothing shorter than the
    /// full 16 hex chars may resolve it.
    #[test]
    fn discriminator_matching_never_accepts_truncated_prefix(disc in prop::collection::vec("[0-9a-fA-F]", 0..24).prop_map(|v| v.concat())) {
        let registry = graphite_core::manifest::load_seed_manifests();
        let full = "bb64facc31c4af14";
        let is_full_or_longer = disc.to_lowercase().starts_with(full);
        if let Some(ix) = registry.find_instruction(JUPITER, &disc) {
            if ix.name == "route_v2" {
                assert!(
                    is_full_or_longer,
                    "discriminator '{}' (truncated prefix of {}) must NOT resolve route_v2",
                    disc, full
                );
            }
        }
        // And a full-length route_v2 discriminator always resolves.
        if is_full_or_longer {
            assert!(registry.find_instruction(JUPITER, &disc).is_some());
        }
    }
}
