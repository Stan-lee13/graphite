// Audit A045: the invariants of `intent_binding::decode_swap`, the decoder
// that reads a swap instruction's attacker-supplied data into the amounts
// the binding holds a request to (and that D-20/D-24 cap L4's wrapped-SOL
// credit at). Shared by the `swap_decoder` fuzz target (which `include!`s
// this file) and `tests/fuzz_seeds_swap_decoder.rs` (which runs it over the
// committed mainnet routes and byte-level variations of them in the normal
// suite). Plain functions only: no `use` that could clash with the
// includer's, and no inner attributes or inner doc comments (`include!` puts
// this after the includer's items).

/// The programs an input's first byte selects: the six whose swaps the Core
/// decodes, and one it does not.
pub const SWAP_DECODER_PROGRAMS: [&str; 7] = [
    graphite_core::intent_binding::JUPITER_V6,
    graphite_core::intent_binding::ORCA_WHIRLPOOLS,
    graphite_core::intent_binding::RAYDIUM_CPMM,
    graphite_core::intent_binding::RAYDIUM_CLMM,
    graphite_core::intent_binding::RAYDIUM_AMM_V4,
    graphite_core::intent_binding::METEORA_DLMM,
    "11111111111111111111111111111111",
];

/// A fuzz input: `[program index][instruction data]`.
pub fn swap_decoder_input(bytes: &[u8]) -> Option<(&'static str, &[u8])> {
    let (&which, data) = bytes.split_first()?;
    Some((
        SWAP_DECODER_PROGRAMS[usize::from(which) % SWAP_DECODER_PROGRAMS.len()],
        data,
    ))
}

/// Decode `data` as an instruction of `program` and hold every accepted
/// decode to what its bytes say. Panics on a broken invariant; returns
/// whether the decode was accepted.
///
/// - never panics, and `None` exactly for a program it does not decode;
/// - an accepted decode consumed every byte: one byte more is refused;
/// - `amount_in` is never 0, and is the layout's input field;
/// - for the Jupiter routes, the amounts are the route's own fields
///   (v1: its trailing 19 bytes), `slippage_bps` is at most 10,000, the
///   platform (and, for v2, positive-slippage) fee is 0, and the minimum
///   is `quoted_out × (10⁴ − slippage) / 10⁴`, never above `quoted_out`;
/// - for the others, the minimum is the layout's threshold field, and the
///   concentrated-liquidity swaps are exact-in.
pub fn check_swap_decode(program: &str, data: &[u8]) -> bool {
    use graphite_core::intent_binding::{decode_swap, DECODED_SWAP_PROGRAMS};
    let Some(result) = decode_swap(program, data) else {
        assert!(
            !DECODED_SWAP_PROGRAMS.contains(&program),
            "{program}: a decoded program answered None"
        );
        return false;
    };
    assert!(
        DECODED_SWAP_PROGRAMS.contains(&program),
        "{program}: decoded, though not a decoded program"
    );
    let Ok(d) = result else {
        return false;
    };
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let what = format!("{} over {}", d.name, hex(data));
    assert!(d.amount_in > 0, "{what}: an input amount of 0");
    assert!(!d.input_account.is_empty(), "{what}: no input account");
    let mut longer = data.to_vec();
    longer.push(0);
    assert!(
        matches!(decode_swap(program, &longer), Some(Err(_))),
        "{what}: accepted with a byte past its layout"
    );
    let u64_at = |i: usize| u64::from_le_bytes(data[i..i + 8].try_into().expect("8 bytes"));
    let u16_at = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
    let held_to_quote = |quoted: u64, slippage: u16| {
        assert!(slippage <= 10_000, "{what}: slippage_bps {slippage}");
        let min = (u128::from(quoted) * u128::from(10_000 - slippage) / 10_000) as u64;
        assert_eq!(
            d.min_out, min,
            "{what}: the minimum is not the quote less slippage"
        );
        assert!(d.min_out <= quoted, "{what}: a minimum above the quote");
    };
    let n = data.len();
    match d.name {
        "Jupiter v6 route" | "Jupiter v6 shared_accounts_route" => {
            assert!(n >= 8 + 4 + 19, "{what}: too short for a route");
            assert_eq!(d.amount_in, u64_at(n - 19), "{what}: in_amount");
            assert_eq!(data[n - 1], 0, "{what}: a platform fee");
            held_to_quote(u64_at(n - 11), u16_at(n - 3));
        }
        "Jupiter v6 route_v2" | "Jupiter v6 shared_accounts_route_v2" => {
            let at = 8 + usize::from(d.name.contains("shared"));
            assert_eq!(d.amount_in, u64_at(at), "{what}: in_amount");
            assert_eq!(u16_at(at + 18), 0, "{what}: a platform fee");
            assert_eq!(u16_at(at + 20), 0, "{what}: a positive-slippage fee");
            held_to_quote(u64_at(at + 8), u16_at(at + 16));
        }
        "Orca Whirlpools swap"
        | "Orca Whirlpools swapV2"
        | "Raydium CLMM swap"
        | "Raydium CLMM swap_v2" => {
            assert_eq!((d.amount_in, d.min_out), (u64_at(8), u64_at(16)), "{what}");
            assert_eq!(data[40], 1, "{what}: not exact-in");
        }
        "Raydium CPMM swap_base_input" | "Meteora DLMM swap" | "Meteora DLMM swap2" => {
            assert_eq!((d.amount_in, d.min_out), (u64_at(8), u64_at(16)), "{what}");
        }
        "Raydium AMM v4 SwapBaseIn" => {
            assert_eq!(n, 17, "{what}");
            assert_eq!((d.amount_in, d.min_out), (u64_at(1), u64_at(9)), "{what}");
        }
        other => panic!("{what}: a decode named {other:?}, which this check does not know"),
    }
    true
}
