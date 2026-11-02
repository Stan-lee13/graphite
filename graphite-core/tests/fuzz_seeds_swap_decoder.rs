//! Audit A045: the swap-data decoder's invariants (`swap_decoder_check`, the
//! same check the `swap_decoder` fuzz target runs) over the committed
//! mainnet routes — every decoded program's instructions in the committed
//! mainnet sample and pinned fixtures (`fuzz/make_seeds.py`) — and over
//! byte-level variations of each: every prefix, every byte set to 0x00,
//! 0x01, 0xff and to itself plus one, and one byte appended. No proptest:
//! the variations are enumerated, so the suite is deterministic and every
//! run checks the same inputs.

mod swap_decoder_check;

use graphite_core::intent_binding::{decode_swap, JUPITER_V6};
use std::path::PathBuf;
use swap_decoder_check::{check_swap_decode, swap_decoder_input};

fn seeds() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/swap_decoder");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn the_committed_mainnet_routes_decode_within_the_decoders_invariants() {
    let all = seeds();
    assert!(all.len() >= 30, "{} swap_decoder seeds", all.len());
    let mut accepted = Vec::new();
    for (name, bytes) in &all {
        let (program, data) = swap_decoder_input(bytes).expect("a program byte");
        if check_swap_decode(program, data) {
            accepted.push(name.as_str());
        }
    }
    // Every route the Core decodes, from mainnet, reaches an accepted decode:
    // Jupiter's four routes, Raydium's CPMM, AMM v4 and CLMM layouts, and the
    // built Orca and Meteora layouts.
    for want in [
        "-0-e517cb977ae3ad2a-",
        "-0-c1209b3341d69c81-",
        "-0-bb64facc31c4af14-",
        "-0-d19853937cfed8e9-",
        "-1-f8c69e91e17587c8-",
        "-1-2b04ed0b1ac91e62-",
        "-2-8fbe5adac41e33de-",
        "-3-2b04ed0b1ac91e62-",
        "-4-09",
        "-5-f8c69e91e17587c8-",
        "-5-414b3f4ceb5b5b88-",
    ] {
        assert!(
            accepted.iter().any(|n| n.contains(want)),
            "no seed {want} decodes; accepted: {accepted:?}"
        );
    }
    assert!(
        accepted.len() >= 20,
        "{} accepted: {accepted:?}",
        accepted.len()
    );
}

#[test]
fn byte_level_variations_of_the_mainnet_routes_hold_the_decoders_invariants() {
    let mut checked = 0usize;
    let mut accepted = 0usize;
    for (_, bytes) in seeds() {
        let (program, data) = swap_decoder_input(&bytes).unwrap();
        let mut run = |d: &[u8]| {
            checked += 1;
            if check_swap_decode(program, d) {
                accepted += 1;
            }
        };
        for cut in 0..data.len() {
            run(&data[..cut]);
        }
        for i in 0..data.len() {
            for b in [0x00, 0x01, 0xff, data[i].wrapping_add(1)] {
                let mut v = data.to_vec();
                v[i] = b;
                run(&v);
            }
        }
        let mut longer = data.to_vec();
        longer.push(0x01);
        run(&longer);
        // The same bytes to the program that is not decoded: always None.
        assert!(decode_swap("11111111111111111111111111111111", data).is_none());
    }
    assert!(checked > 5_000, "{checked} inputs");
    // Most single-byte changes inside an amount still decode: the check
    // ran on accepted decodes, not only on refusals.
    assert!(accepted > 1_000, "{accepted} of {checked} accepted");
}

/// A sanity pin on the check itself: a decode that broke an invariant would
/// be caught. The v1 route's in_amount is its trailing 19 bytes' first 8.
#[test]
fn the_check_reads_the_route_v1_amounts_from_its_trailing_bytes() {
    let data: Vec<u8> = (0..72)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(
                &"e517cb977ae3ad2a01000000c1006400010634f82f0000000092479065050000002c0100"
                    [i..i + 2],
                16,
            )
            .unwrap()
        })
        .collect();
    let d = decode_swap(JUPITER_V6, &data).unwrap().unwrap();
    let n = data.len();
    assert_eq!(
        d.amount_in,
        u64::from_le_bytes(data[n - 19..n - 11].try_into().unwrap())
    );
    assert!(check_swap_decode(JUPITER_V6, &data));
}
