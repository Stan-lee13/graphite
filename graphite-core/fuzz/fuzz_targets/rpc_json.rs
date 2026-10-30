//! RPC JSON response parsing: `simulateTransaction`, account objects
//! (`getAccountInfo` / `getMultipleAccounts` entries) and `getEpochInfo`.
//!
//! Whatever a provider sends must parse or be refused, never panic, and the
//! parsers' own documented rules must hold on everything accepted:
//!
//! - an account with unreadable `lamports`, `owner` or `data` is refused,
//!   never defaulted (an invented balance is indistinguishable from a real
//!   one once it reaches the state diff);
//! - an accepted simulation's derived counters come from the canonical
//!   fields, never a provider-chosen one;
//! - an accepted epoch is internally consistent.
#![no_main]

use graphite_core::rpc_client::{
    account_from_value_for_test, simulation_result_from_value_for_test, EpochInfo,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    for candidate in std::iter::once(&value).chain(value.get("value")) {
        let Ok(sim) = simulation_result_from_value_for_test(candidate) else {
            continue;
        };
        // Round 39 (core-identity): `loadedAddresses` is a SEQUENCE the
        // account indexes read through, so an accepted one is exactly the
        // provider's two lists, in order, every entry a string — and a list
        // with any unreadable entry leaves the whole member unknown, never a
        // shorter list (Round 29, R3).
        let strings = |v: Option<&serde_json::Value>| -> Option<Vec<String>> {
            v?.as_array()?
                .iter()
                .map(|x| x.as_str().map(str::to_string))
                .collect()
        };
        let member = candidate.get("loadedAddresses").filter(|l| !l.is_null());
        let expected =
            member.and_then(|l| Some((strings(l.get("writable"))?, strings(l.get("readonly"))?)));
        assert_eq!(
            sim.loaded_addresses
                .as_ref()
                .map(|l| (l.writable.clone(), l.readonly.clone())),
            expected,
            "loadedAddresses was not read as exactly the provider's lists"
        );
    }

    if let Ok(Some(account)) = account_from_value_for_test("Acct", &value) {
        assert_eq!(
            value.get("lamports").and_then(|v| v.as_u64()),
            Some(account.lamports),
            "an accepted account's balance is the one the response carried"
        );
        assert_eq!(
            value.get("owner").and_then(|v| v.as_str()),
            Some(account.owner.as_str())
        );
        let pair = value.get("data").and_then(|d| d.as_array());
        assert!(
            matches!(pair, Some(p) if p.len() == 2 && p[1].as_str() == Some("base64")),
            "an account was accepted without a base64 data pair"
        );
    }
    if let Ok(None) = account_from_value_for_test("Acct", &value) {
        assert!(
            value.is_null(),
            "only `null` means the account does not exist"
        );
    }

    if let Ok(epoch) = EpochInfo::from_value(&value) {
        assert!(epoch.slots_in_epoch > 0);
        assert!(epoch.slot_index < epoch.slots_in_epoch);
        assert!(epoch.slot_index <= epoch.absolute_slot);
        assert_eq!(epoch.epoch_of(epoch.absolute_slot), Some(epoch.epoch));
        let _ = epoch.epoch_of(0);
        let _ = epoch.epoch_of(u64::MAX);
    }
});
