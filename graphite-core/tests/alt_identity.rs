//! Address lookup tables: identified, not counted.
//!
//! The last aggregate. Everything else in the artifact boundary moved from
//! counting to identity — account universes, instruction membership — and ALT
//! accounts were the remaining place where Graphite could say "there are three
//! of them" and not "they are these three".
//!
//! That mattered because it is the same gap through a different door. A v0
//! transaction can reach an account that appears nowhere in the static key
//! array; if the verified intent is "user → vault A" and the table resolves to
//! vault B, a pipeline reasoning from counts cannot tell.
//!
//! The message carries the table addresses and the indexes. Fetching the tables
//! turns them into addresses Graphite derived itself, rather than addresses the
//! simulator reported — which matters, because `loadedAddresses` comes from the
//! same RPC whose other claims the trust-boundary work spends its time bounding.

use graphite_core::tx_artifact::{
    decode_lookup_table, resolve_lookups, AddressTableLookup, ArtifactMessage, LookupResolveError,
    LOOKUP_TABLE_META_SIZE,
};
use std::collections::HashMap;

const TABLE: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const A: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const B: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const C: &str = "9vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

fn b58(s: &str) -> [u8; 32] {
    let pk = graphite_core::solana_types::Pubkey::from_base58(s).expect("valid pubkey");
    let mut out = [0u8; 32];
    out.copy_from_slice(pk.as_bytes());
    out
}

/// A well-formed, active lookup table account holding `addresses`.
fn table_account(addresses: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
    // deactivation_slot = u64::MAX means "not deactivating".
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    for a in addresses {
        data.extend_from_slice(&b58(a));
    }
    data
}

fn message_with(lookups: Vec<AddressTableLookup>) -> ArtifactMessage {
    ArtifactMessage {
        version: Some(0),
        static_keys: vec![TABLE.to_string()],
        fee_payer: TABLE.to_string(),
        recent_blockhash: TABLE.to_string(),
        signers: vec![TABLE.to_string()],
        writable: vec![TABLE.to_string()],
        instructions: vec![],
        lookups,
    }
}

fn one_table(writable: Vec<u8>, readonly: Vec<u8>) -> ArtifactMessage {
    message_with(vec![AddressTableLookup {
        table: TABLE.to_string(),
        writable_indexes: writable,
        readonly_indexes: readonly,
    }])
}

#[test]
fn indexes_resolve_to_the_addresses_the_table_actually_holds() {
    let msg = one_table(vec![2], vec![0]);
    let mut tables = HashMap::new();
    tables.insert(TABLE.to_string(), table_account(&[A, B, C]));

    let resolved = resolve_lookups(&msg, &tables).expect("must resolve");
    assert_eq!(
        resolved.writable,
        vec![C.to_string()],
        "index 2 is the third entry"
    );
    assert_eq!(
        resolved.readonly,
        vec![A.to_string()],
        "index 0 is the first"
    );
    // Writables first, then readonlies: the order the runtime appends them, so
    // the result lines up with balance arrays and instruction account indexes.
    assert_eq!(
        resolved.all().cloned().collect::<Vec<_>>(),
        vec![C.to_string(), A.to_string()]
    );
}

/// The point of the whole exercise: swapping the table's contents changes WHICH
/// account the transaction reaches, while every count stays identical.
#[test]
fn substituting_the_table_contents_changes_the_resolved_identity() {
    let msg = one_table(vec![0], vec![]);
    let mut honest = HashMap::new();
    honest.insert(TABLE.to_string(), table_account(&[A, B, C]));
    let mut swapped = HashMap::new();
    swapped.insert(TABLE.to_string(), table_account(&[B, A, C]));

    let r1 = resolve_lookups(&msg, &honest).expect("resolves");
    let r2 = resolve_lookups(&msg, &swapped).expect("resolves");
    assert_eq!(
        r1.len(),
        r2.len(),
        "the counts are identical — which is the problem"
    );
    assert_ne!(
        r1.writable, r2.writable,
        "and the identities are not: a count-based check cannot tell these apart"
    );
}

#[test]
fn an_index_past_the_end_of_the_table_is_refused() {
    let msg = one_table(vec![7], vec![]);
    let mut tables = HashMap::new();
    tables.insert(TABLE.to_string(), table_account(&[A, B]));
    assert!(matches!(
        resolve_lookups(&msg, &tables),
        Err(LookupResolveError::IndexOutOfRange {
            index: 7,
            entries: 2,
            ..
        })
    ));
}

#[test]
fn a_missing_table_resolves_nothing_rather_than_what_it_can() {
    // Two tables, one supplied. A partial answer would resolve some indexes and
    // silently mis-attribute the rest.
    let msg = message_with(vec![
        AddressTableLookup {
            table: TABLE.to_string(),
            writable_indexes: vec![0],
            readonly_indexes: vec![],
        },
        AddressTableLookup {
            table: A.to_string(),
            writable_indexes: vec![0],
            readonly_indexes: vec![],
        },
    ]);
    let mut tables = HashMap::new();
    tables.insert(TABLE.to_string(), table_account(&[B]));
    assert!(matches!(
        resolve_lookups(&msg, &tables),
        Err(LookupResolveError::TableMissing { .. })
    ));
}

/// A table on its way out is not one to resolve security-relevant identities
/// against: its contents can stop being authoritative under the transaction.
#[test]
fn a_deactivating_table_is_refused() {
    let mut data = table_account(&[A, B]);
    data[4..12].copy_from_slice(&12_345u64.to_le_bytes());
    assert!(matches!(
        decode_lookup_table(TABLE, &data),
        Err(LookupResolveError::TableDeactivating { slot: 12_345, .. })
    ));
}

#[test]
fn a_malformed_table_is_refused_rather_than_partially_decoded() {
    // Shorter than the header.
    assert!(matches!(
        decode_lookup_table(TABLE, &[0u8; 10]),
        Err(LookupResolveError::TableTooShort { len: 10, .. })
    ));
    // Header plus a partial address: decoding the whole entries and dropping
    // the remainder would shift every later index by one.
    let mut ragged = table_account(&[A, B]);
    ragged.extend_from_slice(&[0u8; 7]);
    assert!(matches!(
        decode_lookup_table(TABLE, &ragged),
        Err(LookupResolveError::TableNotAligned { trailing: 7, .. })
    ));
}

/// Anti-vacuity: if every table were refused, the tests above would pass while
/// resolution never worked.
#[test]
fn a_well_formed_active_table_decodes_completely() {
    let addresses = decode_lookup_table(TABLE, &table_account(&[A, B, C])).expect("decodes");
    assert_eq!(addresses, vec![A.to_string(), B.to_string(), C.to_string()]);
}

/// A message with no lookups resolves to nothing, without error — legacy
/// transactions and v0 transactions that reference no table must not be treated
/// as failures.
#[test]
fn a_message_without_lookups_resolves_empty() {
    let msg = message_with(vec![]);
    let resolved = resolve_lookups(&msg, &HashMap::new()).expect("no lookups, no error");
    assert!(resolved.is_empty());
    assert!(!msg.has_lookup_accounts());
}
