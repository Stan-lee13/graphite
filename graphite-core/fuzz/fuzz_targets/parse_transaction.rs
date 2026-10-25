//! Wire-format parser: legacy, v0 and v1 frames.
//!
//! The parser decides what the signer is about to authorise, so beyond "never
//! panics" each accepted frame must be internally consistent: the fee payer is
//! static key 0, every signer and every writable address is a static key, the
//! runtime-writable set is a subset of what the header marks writable, every
//! instruction's program and accounts resolve inside the message, and the
//! helpers that re-read the same bytes agree with the parse. Round 39: and the
//! parse is injective — the message re-encoded from it is the input's message,
//! byte for byte, inside exactly the signature array its header requires.
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

    // Round 39 (core-identity): the parse is INJECTIVE. Re-encoding what was
    // read reproduces the message bytes exactly, and the frame around them is
    // exactly the signature array the header requires. Two byte strings that
    // read as one transaction are the ambiguity the binding exists to rule
    // out (trailing bytes, a second spelling of a length, a header byte the
    // parse does not reflect), and "internally consistent" alone could not
    // see one.
    let message = tx::message_bytes(data).expect("checked above");
    assert_eq!(
        reencode(&m),
        message,
        "the parse does not determine the message bytes"
    );
    let signatures = 64 * m.signers.len();
    if m.version == Some(1) {
        assert_eq!(data.len(), message.len() + signatures);
        assert_eq!(&data[..message.len()], message);
    } else {
        let mut prefix = Vec::new();
        compact_u16(m.signers.len(), &mut prefix);
        assert_eq!(data.len(), prefix.len() + signatures + message.len());
        assert_eq!(&data[..prefix.len()], &prefix[..]);
        assert_eq!(&data[prefix.len() + signatures..], message);
    }
});

fn compact_u16(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn key_bytes(k: &str) -> [u8; 32] {
    *graphite_core::solana_types::Pubkey::from_base58(k)
        .expect("a parsed key is base58 of 32 bytes")
        .as_bytes()
}

/// The canonical wire form of a parsed message, rebuilt from the parse alone.
fn reencode(m: &tx::ArtifactMessage) -> Vec<u8> {
    let signers = m.signers.len();
    let readonly_signed = m
        .signers
        .iter()
        .filter(|s| !m.header_writable.contains(s))
        .count();
    let readonly_unsigned = m.static_keys[signers..]
        .iter()
        .filter(|k| !m.header_writable.contains(k))
        .count();
    let header = [
        signers as u8,
        readonly_signed as u8,
        readonly_unsigned as u8,
    ];
    let program_index = |ix: &tx::ArtifactInstruction| {
        m.static_keys
            .iter()
            .position(|k| *k == ix.program_id)
            .expect("a program id is a static key") as u8
    };
    let mut out = Vec::new();
    if m.version == Some(1) {
        let v1 = m.v1_config.expect("a v1 message carries its config");
        let mut mask = 0u32;
        if v1.priority_fee.is_some() {
            mask |= 0b11;
        }
        if v1.compute_unit_limit.is_some() {
            mask |= 0b100;
        }
        if v1.loaded_accounts_data_size_limit.is_some() {
            mask |= 0b1000;
        }
        if v1.heap_size.is_some() {
            mask |= 0b1_0000;
        }
        out.push(tx::V1_PREFIX);
        out.extend_from_slice(&header);
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(&key_bytes(&m.recent_blockhash));
        out.push(m.instructions.len() as u8);
        out.push(m.static_keys.len() as u8);
        for k in &m.static_keys {
            out.extend_from_slice(&key_bytes(k));
        }
        if let Some(fee) = v1.priority_fee {
            out.extend_from_slice(&fee.to_le_bytes());
        }
        for v in [
            v1.compute_unit_limit,
            v1.loaded_accounts_data_size_limit,
            v1.heap_size,
        ]
        .into_iter()
        .flatten()
        {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for ix in &m.instructions {
            out.push(program_index(ix));
            out.push(ix.account_indexes.len() as u8);
            out.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
        }
        for ix in &m.instructions {
            out.extend_from_slice(&ix.account_indexes);
            out.extend_from_slice(&ix.data);
        }
        return out;
    }
    if m.version == Some(0) {
        out.push(0x80);
    }
    out.extend_from_slice(&header);
    compact_u16(m.static_keys.len(), &mut out);
    for k in &m.static_keys {
        out.extend_from_slice(&key_bytes(k));
    }
    out.extend_from_slice(&key_bytes(&m.recent_blockhash));
    compact_u16(m.instructions.len(), &mut out);
    for ix in &m.instructions {
        out.push(program_index(ix));
        compact_u16(ix.account_indexes.len(), &mut out);
        out.extend_from_slice(&ix.account_indexes);
        compact_u16(ix.data.len(), &mut out);
        out.extend_from_slice(&ix.data);
    }
    if m.version == Some(0) {
        compact_u16(m.lookups.len(), &mut out);
        for l in &m.lookups {
            out.extend_from_slice(&key_bytes(&l.table));
            compact_u16(l.writable_indexes.len(), &mut out);
            out.extend_from_slice(&l.writable_indexes);
            compact_u16(l.readonly_indexes.len(), &mut out);
            out.extend_from_slice(&l.readonly_indexes);
        }
    }
    out
}
