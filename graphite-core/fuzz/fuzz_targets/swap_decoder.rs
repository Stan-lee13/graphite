//! The swap-data decoder (audit A045): `intent_binding::decode_swap` over
//! arbitrary instruction data for each program whose swaps the Core decodes
//! — Jupiter v6's four routes through every committed Swap variant,
//! Raydium's, Orca's and Meteora's layouts — and one it does not.
//!
//! The input is `[program index][instruction data]`; the seeds are the
//! committed mainnet routes (`fuzz/make_seeds.py`). The invariants, beyond
//! "never panics", are in `tests/swap_decoder_check/mod.rs`, which the
//! normal suite also runs over the seeds (`tests/fuzz_seeds_swap_decoder.rs`):
//! an accepted decode consumed every byte, its amounts are the layout's own
//! fields, slippage is at most 10,000 bps, the route's fees are 0, and the
//! minimum is never above the quote.
#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/swap_decoder_check/mod.rs");

fuzz_target!(|bytes: &[u8]| {
    if let Some((program, data)) = swap_decoder_input(bytes) {
        check_swap_decode(program, data);
    }
});
