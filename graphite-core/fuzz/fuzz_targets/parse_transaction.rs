//! Wire-format parser: legacy, v0 and v1 frames.
//!
//! The parser decides what the signer is about to authorise, so beyond "never
//! panics" each accepted frame must be internally consistent: the fee payer is
//! static key 0, every signer and every writable address is a static key, the
//! runtime-writable set is a subset of what the header marks writable, every
//! instruction's program and accounts resolve inside the message, and the
//! helpers that re-read the same bytes agree with the parse.
#![no_main]

use graphite_core::tx_artifact as tx;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = tx::parse_transaction(data);
    // Determinism: the same bytes always read the same way.
    assert_eq!(parsed, tx::parse_transaction(data));

    // The re-readers must never panic, whatever the frame.
    let _ = tx::unsigned_artifact(data);
    let _ = tx::filled_signature_slots(data);
    let _ = tx::simulation_identity(data);
    let _ = tx::artifact_sha256_of_signed(data);
    let _ = tx::max_frame_bytes(data);
    let _ = tx::is_v1_frame(data);

    let Ok(m) = parsed else { return };

    assert!(
        tx::message_bytes(data).is_ok(),
        "a frame that parses must expose its message bytes"
    );
    assert_eq!(
        m.static_keys.first(),
        Some(&m.fee_payer),
        "fee payer is static key 0"
    );
    assert!(m.signers.iter().all(|s| m.static_keys.contains(s)));
    assert!(m.header_writable.iter().all(|w| m.static_keys.contains(w)));
    assert!(
        m.writable.iter().all(|w| m.header_writable.contains(w)),
        "the runtime only demotes; it never promotes a key to writable"
    );
    assert_eq!(m.v1_config.is_some(), m.version == Some(1));
    if m.version == Some(1) {
        assert!(m.lookups.is_empty(), "v1 has no address lookup tables");
    }

    let static_len = m.static_keys.len();
    let universe = static_len + m.alt_account_count();
    for ix in &m.instructions {
        assert!(
            m.static_keys.contains(&ix.program_id),
            "program ids are static keys"
        );
        assert_eq!(ix.accounts.len(), ix.account_indexes.len());
        for (slot, &i) in ix.accounts.iter().zip(&ix.account_indexes) {
            assert!(
                (i as usize) < universe,
                "account index past the account universe"
            );
            // Static indexes name their key; lookup indexes stay unresolved.
            if (i as usize) < static_len {
                assert_eq!(slot.as_deref(), Some(m.static_keys[i as usize].as_str()));
            } else {
                assert!(slot.is_none());
            }
        }
        let _ = tx::resolve_instruction_accounts(&m, ix, None);
    }
    let _ = tx::runtime_account_list(&m, None);
    let _ = tx::compute_budget_request(&m);
    let _ = tx::durable_nonce(&m);
});
