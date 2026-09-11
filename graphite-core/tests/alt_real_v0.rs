//! Address lookup tables, checked against REAL mainnet v0 transactions.
//!
//! `alt_identity.rs` builds `ArtifactMessage` values directly and proves the
//! resolution rules in isolation. That is worth having and it is not enough:
//! every one of those messages was constructed by the test, so the wire parser
//! never ran, and the ordering rule was checked against my reading of the
//! runtime rather than against the runtime.
//!
//! These fixtures are three real mainnet-beta v0 transactions — one, three and
//! four lookup tables — captured read-only, together with the eight real lookup
//! table accounts they reference and, crucially, `meta.loadedAddresses`: the
//! runtime's OWN record of which accounts those tables resolved to when Solana
//! executed the transaction.
//!
//! That last field is what makes this more than a parse test. Graphite decodes
//! the tables itself, applies its own ordering rule, and the result must equal
//! what the chain recorded. If the 56-byte header offset were wrong, if the
//! ordering were per-table instead of all-writables-then-all-readonlies, or if
//! multi-table ordering followed anything but message order, the comparison
//! fails against ground truth rather than against an assertion I wrote.
//!
//! The attack artifacts are those same transactions re-serialized with exactly
//! one field changed. The fixture builder asserted the round-trip was byte
//! identical before mutating, so each attack differs from a genuine mainnet
//! transaction in the one named way and in no other.
//!
//! Nothing here signs, submits, or touches a live account. The signatures
//! carried by the mutated bytes are the originals and are not valid for them;
//! Graphite is a pre-signature gate and never verifies signatures, so their
//! validity is not what any of these tests turn on.

use base64::Engine;
use graphite_core::tx_artifact::{
    decode_lookup_table, parse_transaction, resolve_lookups, LookupResolveError,
};
use std::collections::HashMap;

fn fixture() -> serde_json::Value {
    let raw = include_str!("../fixtures/artifacts/mainnet_v0_alt.json");
    serde_json::from_str(raw).expect("committed mainnet v0 fixtures must parse")
}

fn b64(v: &serde_json::Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().expect("base64 string"))
        .expect("fixture base64 must decode")
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

/// Every lookup table account in the fixture, keyed by address, in the shape
/// `resolve_lookups` takes.
fn tables(f: &serde_json::Value) -> HashMap<String, Vec<u8>> {
    f["lookup_tables"]
        .as_object()
        .expect("lookup_tables object")
        .iter()
        .map(|(addr, t)| (addr.clone(), b64(&t["data_base64"])))
        .collect()
}

fn transactions(f: &serde_json::Value) -> Vec<serde_json::Value> {
    f["transactions"].as_array().expect("transactions").clone()
}

fn mutation(f: &serde_json::Value, name: &str) -> serde_json::Value {
    f["mutations"]
        .as_array()
        .expect("mutations")
        .iter()
        .find(|m| m["name"] == name)
        .unwrap_or_else(|| panic!("fixture must carry the {name} mutation"))
        .clone()
}

/// The parser reads the lookup section of a real v0 message the same way the
/// RPC does.
///
/// Not a tautology: the fixture's `lookups` came from the node decoding these
/// bytes, and Graphite's came from `parse_transaction` reading them. Two
/// independent decoders of the same wire format agreeing on table addresses and
/// on every index is the check.
#[test]
fn real_mainnet_v0_lookup_sections_parse_as_the_node_reads_them() {
    let f = fixture();
    for tx in transactions(&f) {
        let bytes = b64(&tx["raw_base64"]);
        let m = parse_transaction(&bytes).expect("a real mainnet v0 transaction must parse");
        assert_eq!(m.version, Some(0), "{}", tx["name"]);

        let expected = tx["lookups"].as_array().expect("lookups");
        assert_eq!(
            m.lookups.len(),
            expected.len(),
            "{}: table count",
            tx["name"]
        );
        for (got, want) in m.lookups.iter().zip(expected) {
            assert_eq!(got.table, want["table"].as_str().unwrap(), "table address");
            let w: Vec<u8> = want["writable"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap() as u8)
                .collect();
            let r: Vec<u8> = want["readonly"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(got.writable_indexes, w, "writable indexes");
            assert_eq!(got.readonly_indexes, r, "readonly indexes");
        }
        println!(
            "{}: {} static keys, {} instructions, {} tables, {} ALT accounts",
            tx["name"],
            m.static_keys.len(),
            m.instructions.len(),
            m.alt_table_count(),
            m.alt_account_count()
        );
    }
}

/// The load-bearing test of the whole ALT effort.
///
/// Graphite resolves the tables itself and must land on exactly what Solana
/// recorded — same addresses, same order, same writable/readonly split — for a
/// one-table, a three-table and a four-table transaction.
#[test]
fn graphite_resolution_reproduces_the_runtimes_own_resolution() {
    let f = fixture();
    let tables = tables(&f);
    let mut checked = 0usize;

    for tx in transactions(&f) {
        let bytes = b64(&tx["raw_base64"]);
        let m = parse_transaction(&bytes).expect("must parse");
        let resolved = resolve_lookups(&m, &tables).expect("real active tables must resolve");

        let runtime_w = strings(&tx["runtime_loaded_addresses"]["writable"]);
        let runtime_r = strings(&tx["runtime_loaded_addresses"]["readonly"]);
        assert!(
            !runtime_w.is_empty() || !runtime_r.is_empty(),
            "{}: fixture would be vacuous with nothing loaded",
            tx["name"]
        );

        assert_eq!(
            resolved.writable, runtime_w,
            "{}: writable accounts Graphite resolved differ from what the chain recorded",
            tx["name"]
        );
        assert_eq!(
            resolved.readonly, runtime_r,
            "{}: readonly accounts Graphite resolved differ from what the chain recorded",
            tx["name"]
        );
        println!(
            "{}: {} writable + {} readonly ALT accounts match the runtime exactly",
            tx["name"],
            resolved.writable.len(),
            resolved.readonly.len()
        );
        checked += resolved.len();
    }

    assert!(
        checked >= 60,
        "anti-vacuity: expected the fixtures to exercise many resolved accounts, got {checked}"
    );
}

/// The reason any of this matters: these accounts exist nowhere in the message.
///
/// A verifier reading only `static_keys` sees a transaction that never mentions
/// them, while the runtime hands them to the program as writable.
#[test]
fn alt_resolved_accounts_are_absent_from_the_static_key_list() {
    let f = fixture();
    let tables = tables(&f);
    for tx in transactions(&f) {
        let m = parse_transaction(&b64(&tx["raw_base64"])).expect("must parse");
        let resolved = resolve_lookups(&m, &tables).expect("must resolve");
        for addr in resolved.all() {
            assert!(
                !m.static_keys.contains(addr),
                "{}: {addr} was reachable without the table, weakening the fixture",
                tx["name"]
            );
        }
        assert!(
            !resolved.is_empty(),
            "{}: nothing resolved, so this proves nothing",
            tx["name"]
        );
    }
}

/// Same table, same indexes, same counts — different table.
///
/// Every resolved identity changes and no aggregate moves. This is the "user →
/// vault A vs vault B" substitution carried out on a real transaction against
/// two real mainnet tables.
#[test]
fn substituting_a_real_table_changes_every_identity_while_the_counts_hold() {
    let f = fixture();
    let tables = tables(&f);
    let honest = parse_transaction(&b64(&transactions(&f)[0]["raw_base64"])).expect("must parse");
    let attack = mutation(&f, "table_substituted");
    let attacked = parse_transaction(&b64(&attack["raw_base64"])).expect("must parse");

    assert_ne!(
        honest.lookups[0].table, attacked.lookups[0].table,
        "the mutation must actually change the table"
    );
    assert_eq!(
        honest.lookups[0].writable_indexes, attacked.lookups[0].writable_indexes,
        "indexes are untouched: only the table moved"
    );
    assert_eq!(
        honest.lookups[0].readonly_indexes,
        attacked.lookups[0].readonly_indexes
    );
    assert_eq!(honest.alt_account_count(), attacked.alt_account_count());
    assert_eq!(honest.alt_table_count(), attacked.alt_table_count());

    let a = resolve_lookups(&honest, &tables).expect("must resolve");
    let b = resolve_lookups(&attacked, &tables).expect("must resolve");
    assert_eq!(
        a.len(),
        b.len(),
        "identical counts, which is the whole point"
    );
    let overlap = a.all().filter(|x| b.all().any(|y| y == *x)).count();
    assert_eq!(
        overlap, 0,
        "every account should have changed; {overlap} survived the substitution"
    );
    println!(
        "counts identical ({} accounts), identities entirely disjoint",
        a.len()
    );
}

/// One index moved to another real entry of the same real table.
///
/// The subtler form: one account changes, everything else — including the
/// table, the table count and the account count — is untouched.
#[test]
fn substituting_one_index_changes_exactly_one_identity() {
    let f = fixture();
    let tables = tables(&f);
    let honest = parse_transaction(&b64(&transactions(&f)[0]["raw_base64"])).expect("must parse");
    let attack = mutation(&f, "writable_index_substituted");
    let attacked = parse_transaction(&b64(&attack["raw_base64"])).expect("must parse");

    assert_eq!(honest.lookups[0].table, attacked.lookups[0].table);
    assert_eq!(honest.alt_account_count(), attacked.alt_account_count());

    let a = resolve_lookups(&honest, &tables).expect("must resolve");
    let b = resolve_lookups(&attacked, &tables).expect("must resolve");
    assert_eq!(a.writable.len(), b.writable.len());
    assert_eq!(a.readonly, b.readonly, "only a writable index was touched");
    let differing = a
        .writable
        .iter()
        .zip(&b.writable)
        .filter(|(x, y)| x != y)
        .count();
    assert_eq!(
        differing, 1,
        "exactly one writable account should differ, got {differing}"
    );
    println!(
        "one substituted index: {} -> {}",
        a.writable[0], b.writable[0]
    );
}

/// Privilege, not membership.
///
/// The same account is reached, the resolved set is identical, and the account
/// arrives readonly instead of writable. Anything comparing sets — or counts —
/// cannot see this at all.
#[test]
fn moving_an_index_from_writable_to_readonly_changes_privilege_not_membership() {
    let f = fixture();
    let tables = tables(&f);
    let honest = parse_transaction(&b64(&transactions(&f)[0]["raw_base64"])).expect("must parse");
    let attack = mutation(&f, "privilege_moved_writable_to_readonly");
    let attacked = parse_transaction(&b64(&attack["raw_base64"])).expect("must parse");

    let a = resolve_lookups(&honest, &tables).expect("must resolve");
    let b = resolve_lookups(&attacked, &tables).expect("must resolve");

    assert_eq!(a.len(), b.len(), "membership count unchanged");
    let mut sa: Vec<&String> = a.all().collect();
    let mut sb: Vec<&String> = b.all().collect();
    sa.sort();
    sb.sort();
    assert_eq!(sa, sb, "the same accounts are reached either way");

    assert_ne!(
        a.writable, b.writable,
        "the writable set must differ, or the mutation did nothing"
    );
    assert_eq!(
        a.writable.len(),
        b.writable.len() + 1,
        "one account moved out of writable"
    );
    assert!(
        b.readonly.contains(&a.writable[0]),
        "the moved account should now arrive readonly"
    );
    println!(
        "{} moved writable -> readonly; membership identical",
        a.writable[0]
    );
}

/// An index past the end of a REAL table refuses the whole resolution.
///
/// Not "resolves what it can". A partial address list mis-attributes every
/// index after the gap, which is worse than reporting nothing, because it looks
/// like an answer.
#[test]
fn an_index_past_the_end_of_a_real_table_refuses_everything() {
    let f = fixture();
    let tables = tables(&f);
    let attack = mutation(&f, "index_past_end_of_table");
    let attacked = parse_transaction(&b64(&attack["raw_base64"])).expect("must parse");

    match resolve_lookups(&attacked, &tables) {
        Err(LookupResolveError::IndexOutOfRange { index, entries, .. }) => {
            assert!(
                index as usize >= entries,
                "the refusal must name a genuinely out-of-range index"
            );
            println!("refused: index {index} against a real table of {entries} entries");
        }
        Err(other) => panic!("refused for the wrong reason: {other}"),
        Ok(r) => panic!(
            "resolved {} accounts from a table that does not contain the index",
            r.len()
        ),
    }
}

/// A real lookup table account decodes to the number of addresses its length
/// implies, with the 56-byte header accounted for.
///
/// Anti-vacuity for the refusal tests above: if `decode_lookup_table` rejected
/// everything, they would all pass while resolution never worked.
#[test]
fn real_lookup_table_accounts_decode_completely() {
    let f = fixture();
    let mut total = 0usize;
    for (addr, data) in tables(&f) {
        let decoded = decode_lookup_table(&addr, &data).expect("a real active table must decode");
        assert_eq!(
            decoded.len(),
            (data.len() - graphite_core::tx_artifact::LOOKUP_TABLE_META_SIZE) / 32,
            "{addr}: address count must follow from the account length"
        );
        for a in &decoded {
            assert_eq!(
                bs58::decode(a).into_vec().map(|v| v.len()).unwrap_or(0),
                32,
                "{addr}: every decoded entry must be a 32-byte pubkey"
            );
        }
        total += decoded.len();
    }
    assert!(
        total > 1000,
        "anti-vacuity: the real tables should hold thousands of addresses, got {total}"
    );
    println!("{total} addresses decoded across the fixture's real tables");
}

/// Truncating a real table's data refuses rather than decoding the prefix.
///
/// Same shape as the out-of-range case and a different cause: an RPC that
/// returns a short account must not become a shorter address list.
#[test]
fn a_truncated_real_table_is_refused() {
    let f = fixture();
    let full = tables(&f);
    let (addr, data) = full.iter().next().expect("at least one table");

    // Cut mid-address: still past the header, so this is specifically the
    // alignment check and not the length check.
    let ragged = data[..data.len() - 7].to_vec();
    assert!(matches!(
        decode_lookup_table(addr, &ragged),
        Err(LookupResolveError::TableNotAligned { .. })
    ));

    // Cut below the header entirely.
    let stub = data[..20].to_vec();
    assert!(matches!(
        decode_lookup_table(addr, &stub),
        Err(LookupResolveError::TableTooShort { .. })
    ));
}

/// A table the caller could not fetch resolves nothing, and says which table.
#[test]
fn a_table_missing_from_the_fetch_refuses_by_name() {
    let f = fixture();
    let tx = &transactions(&f)[2]; // the four-table transaction
    let m = parse_transaction(&b64(&tx["raw_base64"])).expect("must parse");
    assert!(m.lookups.len() >= 2, "this test needs several tables");

    // Everything except the first table, which is the realistic partial-fetch
    // failure: `getMultipleAccounts` returned null for one entry.
    let mut partial = tables(&f);
    let dropped = m.lookups[0].table.clone();
    partial.remove(&dropped);

    match resolve_lookups(&m, &partial) {
        Err(LookupResolveError::TableMissing { table }) => assert_eq!(table, dropped),
        Err(other) => panic!("refused for the wrong reason: {other}"),
        Ok(r) => panic!(
            "resolved {} accounts with one of {} tables missing",
            r.len(),
            m.lookups.len()
        ),
    }
}

// -- The chain from an index to a described position ------------------------

/// Every instruction account index resolves against the runtime's own numbering.
///
/// Solana numbers a v0 transaction's accounts as static keys, then ALT
/// writables in message order, then ALT readonlies. An instruction index points
/// into THAT list. Until this landed, an index past the static keys resolved to
/// `None` and the positional comparison skipped it — so for exactly the accounts
/// a v0 transaction reaches without naming them, the chain
/// `index -> address -> described position` was never closed.
#[test]
fn instruction_indexes_resolve_against_the_runtimes_own_numbering() {
    let f = fixture();
    let tables = tables(&f);
    let mut alt_sourced = 0usize;

    for tx in transactions(&f) {
        let m = parse_transaction(&b64(&tx["raw_base64"])).expect("must parse");
        let resolved = resolve_lookups(&m, &tables).expect("must resolve");
        let all = graphite_core::tx_artifact::runtime_account_list(&m, Some(&resolved))
            .expect("a fully resolved message must produce a complete account list");

        assert_eq!(
            all.len(),
            m.static_keys.len() + resolved.len(),
            "{}: the runtime list is the static keys plus every resolved account",
            tx["name"]
        );
        assert_eq!(&all[..m.static_keys.len()], &m.static_keys[..]);
        assert_eq!(
            &all[m.static_keys.len()..m.static_keys.len() + resolved.writable.len()],
            &resolved.writable[..],
            "writables come before readonlies, as the runtime numbers them"
        );

        for ix in &m.instructions {
            let addrs =
                graphite_core::tx_artifact::resolve_instruction_accounts(&m, ix, Some(&resolved))
                    .expect("every index must resolve");
            assert_eq!(addrs.len(), ix.account_indexes.len());
            for (pos, (&index, addr)) in ix.account_indexes.iter().zip(&addrs).enumerate() {
                assert_eq!(
                    addr, &all[index as usize],
                    "{}: instruction position {pos} (index {index}) resolved wrongly",
                    tx["name"]
                );
                if (index as usize) >= m.static_keys.len() {
                    alt_sourced += 1;
                }
            }
        }
    }
    assert!(
        alt_sourced > 0,
        "no instruction position came from a lookup table, so this proves nothing"
    );
    println!("{alt_sourced} instruction account positions resolved through lookup tables");
}

/// Without the tables, nothing is resolved rather than something being guessed.
///
/// A partial list renumbers every position after the gap, so an index would
/// name a real account that is the wrong one — worse than naming nothing,
/// because it looks like an answer.
#[test]
fn an_unresolved_message_yields_no_account_list_rather_than_a_short_one() {
    let f = fixture();
    let tx = &transactions(&f)[0];
    let m = parse_transaction(&b64(&tx["raw_base64"])).expect("must parse");
    assert!(
        graphite_core::tx_artifact::runtime_account_list(&m, None).is_none(),
        "a v0 message with no resolution must not fall back to its static keys"
    );
    for ix in &m.instructions {
        assert!(graphite_core::tx_artifact::resolve_instruction_accounts(&m, ix, None).is_none());
    }

    // A legacy message has no lookups, so its static keys ARE the whole list.
    let legacy: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/artifacts/devnet_transactions.json"
    ))
    .expect("fixtures must parse");
    let bytes: Vec<u8> = legacy["benign_transfer"]["blob"]
        .as_array()
        .expect("blob")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect();
    let lm = parse_transaction(&bytes).expect("must parse");
    assert_eq!(
        graphite_core::tx_artifact::runtime_account_list(&lm, None),
        Some(lm.static_keys.clone()),
    );
}

/// A resolution of the wrong size is refused rather than indexed into.
#[test]
fn a_resolution_that_does_not_describe_this_message_is_refused() {
    use graphite_core::tx_artifact::ResolvedLookups;
    let f = fixture();
    let m = parse_transaction(&b64(&transactions(&f)[0]["raw_base64"])).expect("must parse");
    let wrong = ResolvedLookups {
        writable: vec!["11111111111111111111111111111111".to_string()],
        readonly: vec![],
    };
    assert_ne!(wrong.len(), m.alt_account_count());
    assert!(graphite_core::tx_artifact::runtime_account_list(&m, Some(&wrong)).is_none());
}

/// Why a table's contents cannot change the meaning of an index that already
/// resolved — the question a message digest alone does not answer.
///
/// The digest binds the table ADDRESS and the INDEX, not the address the index
/// resolves to. So the obvious worry is a table mutated between approval and
/// execution: same signed message, different accounts. Solana's own rules close
/// it, and the argument is worth encoding rather than asserting:
///
///   - `ExtendLookupTable` APPENDS. There is no instruction in the Address
///     Lookup Table program that replaces an address at an index, so an index
///     that resolves today resolves to the same address after any extension.
///   - Closing a table requires deactivation first, and the runtime rejects a
///     transaction referencing a deactivated table — it fails rather than
///     resolving differently. Graphite is stricter still: it refuses to resolve
///     a table that is merely deactivating.
///   - A table's address is a PDA over (authority, recent_slot), and a slot
///     cannot be reused, so a closed table cannot be recreated at the same
///     address holding different addresses.
///
/// This encodes the load-bearing clause: extending a real mainnet table leaves
/// every existing index resolving exactly as before.
#[test]
fn extending_a_table_cannot_change_an_index_that_already_resolved() {
    let f = fixture();
    let tables = tables(&f);
    let tx = &transactions(&f)[0];
    let m = parse_transaction(&b64(&tx["raw_base64"])).expect("must parse");
    let before = resolve_lookups(&m, &tables).expect("must resolve");

    // Append 32 addresses to every table, exactly as ExtendLookupTable would.
    let mut extended: HashMap<String, Vec<u8>> = HashMap::new();
    for (addr, data) in &tables {
        let mut grown = data.clone();
        for i in 0u8..32 {
            grown.extend_from_slice(&[i; 32]);
        }
        extended.insert(addr.clone(), grown);
    }
    let after = resolve_lookups(&m, &extended).expect("an extended table still resolves");

    assert_eq!(
        before.writable, after.writable,
        "appending cannot move an address that was already at an index"
    );
    assert_eq!(before.readonly, after.readonly);

    // The contrapositive, which the ALT program does NOT permit and which is
    // therefore the hypothetical the invariant rules out: a table whose
    // existing entries were REPLACED resolves differently.
    let mut replaced = HashMap::new();
    for (addr, data) in &tables {
        let mut swapped = data.clone();
        swapped[graphite_core::tx_artifact::LOOKUP_TABLE_META_SIZE..].reverse();
        replaced.insert(addr.clone(), swapped);
    }
    let reversed = resolve_lookups(&m, &replaced).expect("still well-formed");
    assert_ne!(
        before.writable, reversed.writable,
        "replacing entries changes what an index means, which is why the ALT program has no instruction that does it"
    );
}
