//! SPL Token / Token-2022 account and mint decoders, the Token-2022 TLV
//! extension scanner, and the native-account decoders (nonce, program,
//! ProgramData).
//!
//! These read account bytes an RPC returned. Beyond never panicking, a
//! snapshot built from a token program's bytes must either decode, or be
//! recorded as unreadable — never silently look like an ordinary account
//! with no token view, because the authority checks would then not see it.
#![no_main]

use graphite_core::rpc_client::{decode_program_account, decode_programdata_header};
use graphite_core::state_diff::{
    decode_mint, decode_token2022_powers, decode_token_account, decode_transfer_fee_config,
    decode_transfer_fee_withheld, detect_token2022_extensions, AccountSnapshot,
    SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM,
};
use graphite_core::tx_artifact::decode_nonce_account;
use libfuzzer_sys::fuzz_target;

const SYSTEM: &str = "11111111111111111111111111111111";

fuzz_target!(|data: &[u8]| {
    let _ = decode_token_account(data);
    let _ = decode_mint(data);
    let _ = detect_token2022_extensions(data);
    let _ = decode_token2022_powers(data);
    let _ = decode_transfer_fee_config(data);
    let _ = decode_transfer_fee_withheld(data);
    let _ = decode_nonce_account(SYSTEM, data);
    let _ = decode_program_account(data);
    let _ = decode_programdata_header(data);

    for owner in [SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM] {
        let snap = AccountSnapshot::from_raw("Acct", 1, owner, data);
        assert_eq!(snap.data_len, data.len());
        // A token-program account of a token account's or a mint's size is
        // either decoded or flagged unreadable; never neither — unless the
        // layout's own initialized byte says it is uninitialized, which the
        // token program itself treats as no account.
        let uninitialized =
            (data.len() == 165 && data[108] == 0) || (data.len() == 82 && data[45] == 0);
        if (data.len() == 165 || data.len() == 82) && !uninitialized {
            assert!(
                snap.token.is_some() || snap.mint.is_some() || snap.extensions.malformed.is_some(),
                "token-layout bytes produced no view and no unreadable flag"
            );
        }
        if owner == SPL_TOKEN_PROGRAM {
            assert!(
                snap.extensions.found.is_empty(),
                "classic SPL Token has no extension region"
            );
        }
    }
});
