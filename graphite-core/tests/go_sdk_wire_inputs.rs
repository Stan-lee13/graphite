//! The Go SDK's request bodies are bodies this Core accepts (audit
//! 2026-10-20, G2).
//!
//! A zero-value `graphite.VerificationInput` used to marshal
//! `"wallet_profile":""` and `"account_addresses":null`; serde refuses both,
//! so the SDK's own default produced a 422. And the Go type could not express
//! `WalletProfile::Custom` at all. `sdk/go/testdata/wire_inputs.json` holds
//! what the Go SDK now sends — its `TestInputsMarshalToTheWireTheCoreAccepts`
//! compares its output with that file byte-for-byte in meaning — and this
//! test deserializes the same file with the Core's own type.

use graphite_core::confidence_engine::TrustTier;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::verification::VerificationInput;
use serde_json::Value;

fn wire() -> Value {
    serde_json::from_str(include_str!("../../sdk/go/testdata/wire_inputs.json"))
        .expect("the Go SDK's wire fixture is JSON")
}

fn parse(name: &str) -> VerificationInput {
    serde_json::from_value(wire()[name].clone())
        .unwrap_or_else(|e| panic!("the Core refuses the Go SDK's `{name}` body: {e}"))
}

#[test]
fn the_zero_value_input_deserializes_with_the_default_profile() {
    let input = parse("zero_value");
    assert!(input.account_addresses.is_empty());
    assert_eq!(input.wallet_profile, WalletProfile::Treasury);
}

#[test]
fn a_preset_and_a_custom_profile_deserialize_as_themselves() {
    assert_eq!(parse("preset").wallet_profile, WalletProfile::Gaming);
    assert_eq!(
        parse("custom").wallet_profile,
        WalletProfile::Custom {
            min_confidence: 0.7,
            min_trust_tier: TrustTier::OfficialManifest,
        }
    );
}

/// The two shapes the old SDK sent are the two serde refuses — the reason
/// the fixture omits one and writes the other as `[]`.
#[test]
fn what_the_old_sdk_sent_is_refused() {
    for (field, value) in [
        ("wallet_profile", Value::from("")),
        ("account_addresses", Value::Null),
    ] {
        let mut body = wire()["preset"].clone();
        body[field] = value;
        assert!(
            serde_json::from_value::<VerificationInput>(body).is_err(),
            "`{field}` as the old SDK sent it must be refused, or this fixture proves nothing"
        );
    }
}
