//! Address-lookup-table decoding and v0 lookup resolution.
//!
//! Input: one length byte `n`, then `n` bytes of table account data, then a
//! serialized transaction. Every lookup the transaction declares is resolved
//! against that one table. A table that decodes must account for every byte
//! (no partial address list), and a resolution that is accepted must give the
//! message exactly as many addresses as its lookups index, in the runtime's
//! order (static keys, then lookup writables, then lookup readonlys).
#![no_main]

use graphite_core::tx_artifact as tx;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = (n as usize).min(rest.len());
    // Scale the one-byte length so tables with several addresses are reachable.
    let table_len = (n * 8).min(rest.len());
    let (table, tx_bytes) = rest.split_at(table_len);

    if let Ok(addresses) = tx::decode_lookup_table("Table", table) {
        assert_eq!(
            table.len(),
            tx::LOOKUP_TABLE_META_SIZE + 32 * addresses.len(),
            "an accepted table accounts for every byte"
        );
    }

    let Ok(m) = tx::parse_transaction(tx_bytes) else {
        return;
    };
    let tables: HashMap<String, Vec<u8>> = m
        .lookups
        .iter()
        .map(|l| (l.table.clone(), table.to_vec()))
        .collect();
    let Ok(resolved) = tx::resolve_lookups(&m, &tables) else {
        return;
    };
    let writable_indexes: usize = m.lookups.iter().map(|l| l.writable_indexes.len()).sum();
    let readonly_indexes: usize = m.lookups.iter().map(|l| l.readonly_indexes.len()).sum();
    assert_eq!(resolved.writable.len(), writable_indexes);
    assert_eq!(resolved.readonly.len(), readonly_indexes);

    if let Some(all) = tx::runtime_account_list(&m, Some(&resolved)) {
        assert_eq!(all.len(), m.static_keys.len() + m.alt_account_count());
        assert_eq!(&all[..m.static_keys.len()], &m.static_keys[..]);
        // The runtime refuses a transaction that loads an account twice;
        // an accepted resolution must not produce a duplicate.
        let mut seen = std::collections::HashSet::new();
        assert!(
            all.iter().all(|a| seen.insert(a)),
            "an account is loaded twice"
        );
        for ix in &m.instructions {
            if let Some(accounts) = tx::resolve_instruction_accounts(&m, ix, Some(&resolved)) {
                assert_eq!(accounts.len(), ix.account_indexes.len());
            }
        }
    }
});
